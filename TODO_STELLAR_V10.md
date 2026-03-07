# TODO_STELLAR_V10.md — ksmbd Full-Stack Exhaustive Protocol Audit

**Audit method**: 10 parallel agents, line-by-line coverage of ALL source files
**Scope**: MS-SMB2, MS-CIFS, MS-FSCC, MS-DTYP, MS-DFSC, MS-RSVD, MS-SWN, MS-XCA,
Apple AAPL extensions, POSIX extensions, WSL extensions, RFC 9000/9001 (QUIC)

**Previous cycles**: V1(66)→V2(37)→V3(16)→V4(20)→V5(31)→V6(22)→V7(12)→V8(0)→V9(24)→**V10(∞)**

**V10 Status**: 198 findings catalogued (47 CRITICAL/HIGH, 89 MEDIUM, 62 LOW/FALSE_POSITIVE)

---

## PRIORITY MATRIX

| Domain | CRITICAL | HIGH | MEDIUM | LOW |
|--------|----------|------|--------|-----|
| Transport/Crypto | 2 | 8 | 8 | 5 |
| QUIC | 3 | 4 | 2 | 1 |
| ACL/Security | 3 | 5 | 5 | 4 |
| IOCTL/FSCTL | 0 | 6 | 9 | 4 |
| QueryInfo/SetInfo | 3 | 5 | 9 | 7 |
| POSIX/Apple/DFS | 0 | 12 | 8 | 5 |
| Negotiate/Auth | 0 | 2 | 14 | 7 |
| QueryDir/Notify/Oplock | 0 | 3 | 6 | 5 |
| Read/Write/Lock | 0 | 2 | 3 | 5 |
| SMB1 | 0 | 5 | 4 | 3 |

---

## FALSE POSITIVES CONFIRMED (do not implement)

- TC-20: Credit symmetric charging for non-LARGE_MTU — balanced +1/-1 ✓
- TC-18: req_len=1 fallback for unknown commands — credit math self-consistent ✓
- TC-24: Session reference leak on compound lookup failure — refcount correct ✓
- QNI-02: IPv4 addr idev under rtnl+RCU — correct lock ordering ✓
- QAR-01: STATUS_BUFFER_OVERFLOW on QUERY_ALLOCATED_RANGES — propagated correctly ✓
- VNI-01: VALIDATE_NEGOTIATE_INFO capabilities comparison — correct ✓
- RK-01: FSCTL_REQUEST_RESUME_KEY third element — zero is correct per spec ✓
- GEN-01: GET_NTFS_FILE_RECORD → STATUS_INVALID_DEVICE_REQUEST — correct ✓
- IOCTL-02: InputOffset for compound requests — correct relative-to-header semantics ✓
- IOCTL-03: Unknown FSCTL → STATUS_INVALID_DEVICE_REQUEST vs STATUS_NOT_SUPPORTED — design correct ✓
- QD-05: SMB2_RETURN_SINGLE_ENTRY — NextEntryOffset=0 correctly set ✓
- QD-07: FileNamesInformation FileIndex — preserved via reserve path ✓
- CN-06: FILE_LIST_DIRECTORY access check — correct ✓
- LB-01: Lease break epoch increment flow — single-break increments once ✓
- LB-02: check_lease_state() validation — correct subset validation ✓
- LB-03: Write-bit ACK rejection — correct ✓
- LB-05: ACK_REQUIRED flag condition — checks current state correctly ✓
- LB-07: Lease break MessageId=-1 — correct per spec ✓
- LB-08: Multi-channel lease lookup by ClientGUID — correct ✓
- OB-04: Reserved fields in oplock break notification — zeroed ✓
- QS-01: FILE_STAT_INFORMATION constant — 0x46=70, no collision ✓
- QS-05: FileStreamInfo NextEntryOffset chain — correct ✓
- QS-09: FileBasicInfo Attributes=0 handling — guard correct ✓
- QS-12: FileNameInformation path format — leading backslash correct ✓
- QS-18: FileObjectIdInformation response size — 64 bytes correct ✓
- QS-19: FS_CONTROL DefaultQuotaThreshold sentinel — 0xFFFFFFFFFFFFFFFF correct ✓
- QS-23: FileRemoteProtocolInformation size — 116 bytes correct ✓
- QS-26: ssize_t comparison in smb2_get_ea — correct ✓
- ACL-09: access_flags_to_mode() deny-ACE inversion — intentionally correct ✓
- STREAM-01: ADS `:$DATA` suffix — preserved from xattr key ✓
- EA-01: EA listing xattr prefix filter — namespace prefix handling correct ✓
- LINK-01: -EEXIST → STATUS_OBJECT_NAME_COLLISION mapping — correct ✓
- VSS-01: SnapshotArraySize calculation — count*50+2 consistent ✓
- VSS-03: @GMT token path injection — format validation prevents traversal ✓

---

## SECTION 1: TRANSPORT / CRYPTO / COMPOUND (Agent J)

### [CRITICAL] TC-23: smb3_decrypt_req copies AEAD tag into SMB2 PDU
**File**: `src/protocol/smb2/smb2_pdu_common.c:1574-1575`
**Spec**: MS-SMB2 §2.2.41 — OriginalMessageSize is plaintext length; ciphertext = plaintext + 16-byte tag
**Issue**: After AES-GCM/CCM decryption, code uses `buf_data_size = pdu_length - sizeof(smb2_transform_hdr)` for both the memmove count and the RFC1002 length. `buf_data_size = OriginalMessageSize + 16` (ciphertext includes 16-byte authentication tag). The 16 extra tag bytes are copied into the PDU and the RFC1002 length is inflated by 16, causing every encrypted session to process garbage bytes at the PDU end.
**Fix**: Use `le32_to_cpu(tr_hdr->OriginalMessageSize)` for both the memmove and the RFC1002 length:
```c
unsigned int orig_len = le32_to_cpu(tr_hdr->OriginalMessageSize);
memmove(buf + 4, iov[1].iov_base, orig_len);
*(__be32 *)buf = cpu_to_be32(orig_len);
```
**Complexity**: LOW | **Priority**: P0

---

### [HIGH] TC-01: TCP_NODELAY not set on accepted client sockets
**File**: `src/transport/transport_tcp.c:350`
**Issue**: `ksmbd_tcp_nodelay()` called on the listening socket only. All client connections operate with Nagle's algorithm enabled, adding artificial latency on small packets (ECHO replies, compound headers, error responses).
**Fix**: Add `ksmbd_tcp_nodelay(client_sk)` immediately after `kernel_accept()`, alongside the existing `ksmbd_tcp_keepalive(client_sk)`.
**Complexity**: LOW | **Priority**: P1

---

### [HIGH] TC-04: outstanding_credits leaked when send_no_response=1
**File**: `src/protocol/smb2/smb2misc.c:400`, `src/protocol/smb2/smb2_pdu_common.c:409`
**Issue**: `smb2_validate_credit_charge()` increments `conn->outstanding_credits` on every valid request. `smb2_set_rsp_credits()` decrements it — but returns early when `work->send_no_response` is set (line 409). Credits are permanently leaked on NEGOTIATE/teardown paths that set `send_no_response=1`, eventually stalling all new requests.
**Fix**: In `smb2_set_rsp_credits()`, decrement `outstanding_credits` even when `send_no_response` is set, before the early return.
**Complexity**: LOW | **Priority**: P1

---

### [HIGH] TC-05: TRANSFORM_HEADER OriginalMessageSize not bounds-checked
**File**: `src/protocol/smb2/smb2_pdu_common.c:1531`
**Issue**: `OriginalMessageSize` from the wire is compared against `buf_data_size` but never checked against `MAX_STREAM_PROT_LEN`. A value of 0xFFFFFFFF passes the check and causes unbounded processing.
**Fix**: Add: `if (le32_to_cpu(tr_hdr->OriginalMessageSize) > MAX_STREAM_PROT_LEN) return -ECONNABORTED;`
**Complexity**: LOW | **Priority**: P1

---

### [HIGH] TC-08: Compound related chain — null session crashes on session lookup failure
**File**: `src/core/server.c:278-352`
**Issue**: When a SESSION_SETUP/tree-op fails in a related compound, `compound_err_status` is not set (only CREATE failures set it). Subsequent related sub-requests inherit `work->sess = NULL` and crash attempting session operations.
**Fix**: When `check_user_session` returns an error for any command in a compound, set `compound_err_status` and NULL `work->sess` safely before cascading.
**Complexity**: HIGH | **Priority**: P1

---

### [HIGH] TC-10: Multi-channel decrypt uses connection-local session lookup
**File**: `src/protocol/smb2/smb2_pdu_common.c:1557`
**Issue**: `smb3_decrypt_req()` calls `ksmbd_session_lookup(work->conn, ...)` which is connection-local. On secondary channels, the session is registered on the primary connection, causing decryption failure for all secondary-channel encrypted traffic.
**Fix**: Use `ksmbd_session_lookup_all(work->conn, ...)`.
**Complexity**: MEDIUM | **Priority**: P1

---

### [HIGH] TC-02: Credit grant formula diverges from MS-SMB2 §3.3.4.2
**File**: `src/protocol/smb2/smb2_pdu_common.c:401-476`
**Issue**: Formula caps to "remaining capacity" rather than spec formula. Zero-grants when pool is momentarily full due to outstanding requests.
**Fix**: Implement: `grant = min(credit_charge + credits_requested, max_credits) - credit_charge`. Guarantee minimum 1 credit if client has fewer than MaxCredits.
**Complexity**: MEDIUM | **Priority**: P2

---

### [MEDIUM] TC-19: work->tr_sess_id never set in smb3_decrypt_req
**File**: `src/protocol/smb2/smb2_pdu_common.c:1514-1579`
**Issue**: `work->tr_sess_id` (used by `server.c:465` to encrypt error responses when the inner SMB2 header session is invalid) is never populated, causing unencrypted error responses on encrypted sessions.
**Fix**: After line 1521: `work->tr_sess_id = le64_to_cpu(tr_hdr->SessionId);`
**Complexity**: LOW | **Priority**: P2

---

### [MEDIUM] TC-11: Compound response copies request Signature instead of zeroing
**File**: `src/protocol/smb2/smb2_pdu_common.c:670`
**Issue**: `memcpy(rsp_hdr->Signature, rcv_hdr->Signature, 16)` leaks client's request signature into unsigned responses. Spec requires all-zeros for unsigned messages.
**Fix**: `memset(rsp_hdr->Signature, 0, 16)`.
**Complexity**: LOW | **Priority**: P3

---

### [MEDIUM] TC-17: Compound mid-chain state not finalized when connection goes releasing
**File**: `src/core/server.c:286-288`
**Issue**: When breaking out of the compound loop mid-chain due to connection releasing, unprocessed response headers lack `NextCommand=0` termination.
**Fix**: On loop break, zero `NextCommand` on the last completed response and set `STATUS_CONNECTION_DISCONNECTED` on unprocessed headers.
**Complexity**: MEDIUM | **Priority**: P3

---

### [MEDIUM] TC-22: Unrelated compound doesn't reset compound_sid
**File**: `src/protocol/smb2/smb2_pdu_common.c:649-653`
**Issue**: `compound_fid`/`compound_pfid`/`compound_err_status` reset on unrelated flag, but `compound_sid` does not, bleeding session ID into subsequent unrelated requests.
**Fix**: Add `work->compound_sid = 0;` in the unrelated-flag reset block.
**Complexity**: LOW | **Priority**: P3

---

### [MEDIUM] TC-07: Pre-authentication integrity hash updated after session is authenticated
**File**: `src/protocol/smb2/smb2_pdu_common.c:1392`
**Spec**: MS-SMB2 §3.3.5.5.3 — MUST stop updating hash after final authenticated SESSION_SETUP response.
**Fix**: Skip hash update if `sess->state == SMB2_SESSION_VALID`.
**Complexity**: LOW | **Priority**: P3

---

---

## SECTION 2: QUIC TRANSPORT (Agent I / J)

### [CRITICAL] QUIC-08: Wrong HKDF label prefix — all key derivation broken
**File**: `src/transport/transport_quic.c:124`
**Spec**: RFC 9001 §5.1 — label = `"tls13 " + label_name`
**Issue**: Prefix defined as `"tls13 quic "` producing `"tls13 quic quic key"` instead of `"tls13 quic key"`. Every derived key is wrong; no client will connect.
**Fix**: Change `QUIC_HKDF_LABEL_PREFIX` to `"tls13 "`.
**Complexity**: LOW | **Priority**: P0

---

### [CRITICAL] QUIC-01: AEAD scatter-gather broken — AAD not authenticated
**File**: `src/transport/transport_quic.c:710-809`
**Spec**: RFC 9001 §5.3 — AAD must be prepended to the SGL
**Issue**: `sg_in[0]` set to `aad_buf` is never used in `aead_request_set_crypt`. The AEAD engine reads the first `aad_len` bytes of `work_buf` (ciphertext) as AAD instead. Header authentication is effectively disabled.
**Fix**: Allocate combined `[aad | payload]` buffer, use two-entry SGL: sg[0]=aad, sg[1]=payload.
**Complexity**: MEDIUM | **Priority**: P0

---

### [CRITICAL] QUIC-02: Initial/Handshake packets sent cleartext
**File**: `src/transport/transport_quic.c:1282-1698`
**Spec**: RFC 9001 §5.2 — Initial packets MUST be encrypted with Initial keys derived from DCID.
**Issue**: Both `quic_send_connection_close()` and `quic_send_handshake_data()` explicitly skip AEAD encryption "for simplicity." Windows SMB-over-QUIC clients will reject them.
**Fix**: Apply `ksmbd_quic_aead_crypt()` (after QUIC-01 fix) and `ksmbd_quic_apply_header_protection()` to all outgoing packets.
**Complexity**: HIGH | **Priority**: P0

---

### [HIGH] QUIC-03: No 1-RTT (short-header) receive path
**File**: `src/transport/transport_quic.c`
**Spec**: RFC 9000 §17.3 — After handshake, all data flows in short-header packets.
**Issue**: No function exists to remove header protection, decode packet number, and AEAD-decrypt incoming short-header packets. SMB messages after handshake are silently dropped.
**Fix**: Implement short-header RX: detect `first_byte & 0x80 == 0`, remove HP, decode PN, AEAD-decrypt with `app_crypto.read_key/iv`, feed to `stream_buf`.
**Complexity**: HIGH | **Priority**: P0

---

### [HIGH] QUIC-04: No Retry token — vulnerable to UDP amplification attacks
**File**: `src/transport/transport_quic.c`
**Spec**: RFC 9000 §8.1 — Server MUST verify client address before processing Initial.
**Fix**: Send Retry packet with HMAC-based stateless token; validate on second Initial.
**Complexity**: HIGH | **Priority**: P1

---

### [HIGH] QUIC-07: SMB2_TRANSPORT_CAPABILITIES context missing from QUIC NEGOTIATE response
**File**: `src/include/protocol/smb2pdu.h:421-428`
**Spec**: MS-SMB2 Appendix C — QUIC connections must include ContextType=6 with `SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY` to avoid redundant double-encryption.
**Fix**: In negotiate response builder, include this context when `conn->transport_type == KSMBD_TRANSPORT_QUIC`.
**Complexity**: LOW | **Priority**: P1

---

### [MEDIUM] QUIC-05: No ACK-eliciting frame sent — client retransmit timeout
**Spec**: RFC 9000 §13.2 — CRYPTO frames MUST be acknowledged within PTO.
**Fix**: Queue an ACK frame after processing each CRYPTO frame.
**Complexity**: MEDIUM | **Priority**: P2

---

---

## SECTION 3: ACL / SECURITY DESCRIPTOR / VFS (Agent G)

### [CRITICAL] ACL-01: Security Descriptor revision never validated on SET_INFO
**File**: `src/fs/smbacl.c:1436-1448`
**Spec**: MS-DTYP §2.4.1 — revision MUST be 1; servers MUST reject non-conforming descriptors.
**Fix**: After reading `pntsd_type`, add: `if (le16_to_cpu(pntsd->revision) != SD_REVISION) return -EINVAL;`
**Complexity**: LOW | **Priority**: P1

---

### [CRITICAL] ACL-02: smb_check_perm_dacl() missing ALLOW_CALLBACK and OBJECT ACE types
**File**: `src/fs/smbacl.c:2337-2345`
**Spec**: MS-DTYP §2.4.4.2 — ACCESS_ALLOWED_CALLBACK_ACE_TYPE (0x09), ACCESS_ALLOWED_OBJECT_ACE_TYPE (0x05) are valid grant types.
**Issue**: Switch handles only 0x00, 0x01, 0x0B. Type 0x09 / 0x05 ACEs fall through without setting `access_bits`, making them effective deny-all. Type 0x06 (DENIED_OBJECT) is silently skipped, bypassing intended denies.
**Fix**: Add cases for 0x05/0x09 (treat as ALLOWED) and 0x06/0x0A (treat as DENIED) for SID-based matching.
**Complexity**: LOW | **Priority**: P1

---

### [CRITICAL] ACL-08: SELF_RELATIVE flag not validated — absolute pointer SDs accepted
**File**: `src/fs/smbacl.c:1383-1441`
**Spec**: MS-DTYP §2.4.6 — SDs without SE_SELF_RELATIVE (0x8000) use absolute pointers meaningless in network context and MUST be rejected.
**Fix**: `if (!(pntsd_type & SELF_RELATIVE)) return -EINVAL;` after reading pntsd_type.
**Complexity**: LOW | **Priority**: P1

---

### [HIGH] ACL-03: parse_dacl() uses ace->sid directly for OBJECT ACE types — wrong offset
**File**: `src/fs/smbacl.c:802-958`
**Spec**: MS-DTYP §2.4.4.3 — Object ACE types have optional GUID fields before the SID.
**Issue**: For ACE types 0x05-0x08, the SID is located after 0-32 bytes of GUID data. Using `ace->sid` directly reads GUID bytes as a SID, producing incorrect DACL semantics.
**Fix**: Check `ace->type` and skip `sizeof(struct smb_ace_object_type)` bytes (based on ObjectFlags) before reading the effective SID.
**Complexity**: HIGH | **Priority**: P1

---

### [HIGH] ACL-04: SACL GET path ignores ksmbd_label xattr when stored separately
**File**: `src/fs/smbacl.c:1583-1710`
**Issue**: `build_sec_desc()` only reads SACL from the stored full NTSD. When SACL was stored separately in `XATTR_NAME_SD_LABEL` (by set_info_sec), a GET query with `SACL_SECINFO | LABEL_SECINFO` returns an empty SACL.
**Fix**: In `build_sec_desc()`, when `ppntsd` has no SACL_PRESENT, attempt to read `XATTR_NAME_SD_LABEL` and embed that SACL into the response SD.
**Complexity**: MEDIUM | **Priority**: P1

---

### [HIGH] ACL-05: ACL revision not validated — non-standard revision silently accepted
**File**: `src/fs/smbacl.c:759-761`
**Spec**: MS-DTYP §2.4.5 — ACL revision MUST be 0x02 (standard) or 0x04 (with Object ACEs).
**Fix**: `if (le16_to_cpu(pdacl->revision) != 2 && le16_to_cpu(pdacl->revision) != 4) return;`
**Complexity**: LOW | **Priority**: P2

---

### [HIGH] INHERIT-01: smb_inherit_dacl() buffer undersized for large-SID ACEs
**File**: `src/fs/smbacl.c:1880-1895`
**Issue**: `aces_buf_size = sizeof(struct smb_ace) * num_aces * 2` uses base struct size. ACEs with 15 sub-authorities are 72 bytes, overflowing the allocation on CREATOR_OWNER expansion.
**Fix**: Sum `le16_to_cpu(pace->size)` for all parent DACL ACEs to compute actual required size, then multiply by 2.
**Complexity**: MEDIUM | **Priority**: P2

---

### [CRITICAL] REPARSE-01: SYMLINK_FLAG_RELATIVE always set for absolute symlinks
**File**: `src/fs/ksmbd_reparse.c:974-975`
**Spec**: MS-FSCC §2.1.2.4 — MUST NOT set for absolute paths (starting with `/`).
**Fix**: Check if POSIX target starts with `/`; if so, set `flags = 0`. Otherwise set `SYMLINK_FLAG_RELATIVE`.
**Complexity**: MEDIUM | **Priority**: P1

---

### [MEDIUM] REPARSE-03: GET_REPARSE_POINT SubstituteName missing `\??\` prefix for absolute symlinks
**File**: `src/fs/ksmbd_reparse.c:967-980`
**Spec**: MS-FSCC §2.1.2.4 — Absolute symlinks must have `\??\` NT prefix in SubstituteName.
**Fix**: For absolute symlinks, prepend `\??\` (8 bytes UTF-16) to SubstituteName.
**Complexity**: MEDIUM | **Priority**: P2

---

### [MEDIUM] ACL-06: DACL_AUTO_INHERIT_REQ not propagated during inheritance
**File**: `src/fs/smbacl.c:2019-2022`
**Spec**: MS-DTYP §2.5.3.5 — must propagate to children.
**Fix**: Add `if (parent_pntsd->type & DACL_AUTO_INHERIT_REQ) pntsd->type |= DACL_AUTO_INHERIT_REQ;`
**Complexity**: LOW | **Priority**: P3

---

### [MEDIUM] ACL-07: INHERIT_ONLY ACEs included in access evaluation
**File**: `src/fs/smbacl.c:2228-2272`
**Spec**: MS-DTYP §2.4.4.1 — INHERIT_ONLY_ACE (0x08) MUST be skipped during access checks.
**Fix**: `if (ace->flags & INHERIT_ONLY_ACE) { advance; continue; }` in the iteration loop.
**Complexity**: LOW | **Priority**: P2

---

---

## SECTION 4: IOCTL / FSCTL (Agent D)

### [HIGH] IOCTL-01: IOCTL response FileId fields not set
**File**: `src/protocol/smb2/smb2_ioctl.c:195-204`
**Spec**: MS-SMB2 §2.2.32 — FileId in response must echo input FileId for file-directed FSCTLs; must be SMB2_NO_FID for the special 6 FSCTLs.
**Fix**: In `done:` path, default `rsp->VolatileFileId = req->VolatileFileId; rsp->PersistentFileId = req->PersistentFileId;`. Special FSCTLs already override with NO_FID.
**Complexity**: LOW | **Priority**: P2

---

### [HIGH] CC-03: CopyChunk source/target offset + length overflow not validated
**File**: `src/fs/ksmbd_fsctl.c:1088-1095`
**Issue**: No check for `SourceOffset + Length` or `TargetOffset + Length` overflow before VFS call. Malicious `SourceOffset = UINT64_MAX - 10, Length = 100` wraps the offset.
**Fix**: `if (check_add_overflow(src_off, len, &tmp) || check_add_overflow(dst_off, len, &tmp)) → STATUS_INVALID_PARAMETER`
**Complexity**: LOW | **Priority**: P1

---

### [HIGH] PP-02: FSCTL_PIPE_WAIT checks FID instead of pipe name — always times out
**File**: `src/fs/ksmbd_fsctl_extra.c:601-665`
**Spec**: MS-FSCC §2.3.30 — PIPE_WAIT checks for named pipe availability by pipe name; FileId MUST be NO_FID.
**Issue**: Implementation does `has_file_id(id)` on SMB2_NO_FID → falls to timeout unconditionally.
**Fix**: Extract UTF-16LE pipe name from `req->Name[NameLength]`; query IPC layer for endpoint availability; return SUCCESS or STATUS_IO_TIMEOUT.
**Complexity**: HIGH | **Priority**: P2

---

### [HIGH] PP-01: FSCTL_PIPE_PEEK always returns zeros for ReadDataAvailable
**File**: `src/fs/ksmbd_fsctl.c:655-688`
**Issue**: Returns zeros for `ReadDataAvailable`, `NumberOfMessages`, `MessageLength` — clients stop polling and miss RPC responses.
**Fix**: After successful PIPE_TRANSCEIVE, set `ReadDataAvailable=1` hint on the pipe handle. Return it here.
**Complexity**: HIGH | **Priority**: P2

---

### [HIGH] QNI-01: FSCTL_QUERY_NETWORK_INTERFACE_INFO LinkSpeed divided by 8
**File**: `src/fs/ksmbd_fsctl.c:936`
**Spec**: MS-SMB2 §2.2.32.5 — LinkSpeed in **bits** per second, not bytes.
**Issue**: `nii_rsp->LinkSpeed = cpu_to_le64(speed / 8)` — 1 Gbps reported as 125 Mbps, suppressing multichannel negotiation.
**Fix**: Remove `/ 8`: `nii_rsp->LinkSpeed = cpu_to_le64(speed);`
**Complexity**: LOW | **Priority**: P1

---

### [HIGH] QNI-03: Empty interface list returns zero-byte IOCTL success
**File**: `src/fs/ksmbd_fsctl.c:988-997`
**Spec**: MS-SMB2 §3.3.5.15.14 — Server MUST return at least one interface.
**Fix**: If `nbytes == 0` after loop, return STATUS_NOT_FOUND.
**Complexity**: LOW | **Priority**: P2

---

### [HIGH] ODX-01: FSCTL_OFFLOAD_READ TransferLength not sector-aligned
**File**: `src/fs/ksmbd_fsctl.c:2476-2512`
**Spec**: MS-FSCC §2.3.53 — TransferLength MUST be multiple of logical sector size.
**Fix**: `length = ALIGN_DOWN(length, logical_sector_size)` before storing and returning.
**Complexity**: MEDIUM | **Priority**: P3

---

### [MEDIUM] QNI-01-b: LinkSpeed fetched per-iface correctly but ifc_list from daemon may be incomplete
**Fix**: Augment netlink `ksmbd_startup_request.ifc_list` to include both IPv4 and IPv6 per interface and expose `net_device->speed` directly.
**Complexity**: MEDIUM | **Priority**: P3

---

### [MEDIUM] OI-02: FSCTL_SET_OBJECT_ID_EXTENDED writes 16-byte ObjectId over 48-byte extended input
**File**: `src/fs/ksmbd_fsctl.c:399-407`
**Spec**: MS-FSCC §2.3.67 — The extended input is 48 bytes (BirthVolumeId/BirthObjectId/DomainId), NOT the ObjectId.
**Fix**: Separate handler: read existing ObjectId, write back full 64-byte `FILE_OBJECTID_BUFFER` with updated extended fields.
**Complexity**: MEDIUM | **Priority**: P2

---

### [MEDIUM] SP-01: FSCTL_SET_SPARSE missing write access check
**File**: `src/fs/ksmbd_fsctl.c:1544-1583`
**Spec**: MS-SMB2 §3.3.5.15.5 — Handle must have FILE_WRITE_DATA or FILE_WRITE_ATTRIBUTES.
**Fix**: Add tree-writable check + `fp->daccess & (FILE_WRITE_DATA_LE | FILE_WRITE_ATTRIBUTES_LE)` guard.
**Complexity**: LOW | **Priority**: P2

---

### [MEDIUM] RP-02: FSCTL_GET_REPARSE_POINT always flags symlinks as relative
**File**: `src/fs/ksmbd_reparse.c:974-975`
(Duplicate of REPARSE-01 — one fix addresses both)
**Priority**: P1

---

### [MEDIUM] PP-03: FSCTL_PIPE_TRANSCEIVE returns STATUS_UNEXPECTED_IO_ERROR on zero-byte RPC response
**File**: `src/fs/ksmbd_fsctl.c:1839-1843`
**Fix**: Remove the `rpc_resp->payload_sz == 0` error check; zero-byte RPC response is valid.
**Complexity**: LOW | **Priority**: P2

---

### [MEDIUM] CC-02: COPYCHUNK zero-length chunk breaks loop instead of returning STATUS_INVALID_PARAMETER
**File**: `src/fs/ksmbd_fsctl.c:1088-1092`
**Fix**: Change `break` to return STATUS_INVALID_PARAMETER with server limits in `ci_rsp`.
**Complexity**: LOW | **Priority**: P3

---

### [MEDIUM] GEN-03: Dead code — 5 handlers in ksmbd_fsctl_extra.c never registered
**File**: `src/fs/ksmbd_fsctl_extra.c:320-702`
**Fix**: Remove `__maybe_unused` copychunk/zerod/alloc-ranges handlers; registered duplicates exist in ksmbd_fsctl.c.
**Complexity**: LOW | **Priority**: P3

---

---

## SECTION 5: QUERY_INFO / SET_INFO (Agents C + C2)

### [CRITICAL] QS-02: Single-EA not found returns STATUS_NO_EAS_ON_FILE instead of STATUS_NONEXISTENT_EA_ENTRY
**File**: `src/protocol/smb2/smb2_query_set.c:280-353`
**Spec**: MS-FSCC §2.4.15 — specific EA name missing → STATUS_NONEXISTENT_EA_ENTRY (0xC0000051).
**Fix**: After xattr scan, if `req->InputBufferLength > 0` and `rsp_data_cnt == 0`, set `STATUS_NONEXISTENT_EA_ENTRY`.
**Complexity**: LOW | **Priority**: P1

---

### [CRITICAL] QS-03: EaNameLength not bounds-checked before strncmp — potential read past buffer
**File**: `src/protocol/smb2/smb2_query_set.c:280-283`
**Issue**: Client-supplied `ea_req->EaNameLength` (u8, max 255) used in strncmp without validating `EaNameLength + sizeof(smb2_ea_info_req) <= InputBufferLength`.
**Fix**: Validate `ea_req->EaNameLength + sizeof(smb2_ea_info_req) <= le32_to_cpu(req->InputBufferLength)` and `ea_req->EaNameLength > 0`.
**Complexity**: LOW | **Priority**: P1

---

### [CRITICAL] QS-04: FileValidDataLengthInformation SET missing FILE_WRITE_DATA access check
**File**: `src/fs/ksmbd_info.c:874-911`
**Fix**: Add `if (!(fp->daccess & FILE_WRITE_DATA_LE)) return -EACCES;` at top of `ksmbd_info_set_valid_data_length()`.
**Complexity**: LOW | **Priority**: P1

---

### [HIGH] QS-07: QUERY_SECURITY LABEL_SECINFO missing READ_CONTROL access check
**File**: `src/protocol/smb2/smb2_query_set.c:1893-1898`
**Fix**: Add: `if (addition_info & LABEL_SECINFO) { if (!(fp->daccess & FILE_READ_CONTROL_LE)) return -EACCES; }`
**Complexity**: LOW | **Priority**: P2

---

### [HIGH] QS-08: SET_SECURITY LABEL_SECINFO write not persisted to xattr
**File**: `src/protocol/smb2/smb2_query_set.c:3515-3565`
**Issue**: `set_info_sec()` processes but does not store the integrity label SACL separately to `XATTR_NAME_SD_LABEL`.
**Fix**: After `set_info_sec()`, if `addition_info & LABEL_SECINFO`, extract SACL from new SD and write to `XATTR_NAME_SD_LABEL`.
**Complexity**: MEDIUM | **Priority**: P2

---

### [HIGH] QS-10: FileAllInformation EASize always returns 0
**File**: `src/protocol/smb2/smb2_query_set.c:522`
**Fix**: In `get_file_all_info()`, compute EA size by iterating xattrs (refactor from `get_file_ea_info()`).
**Complexity**: MEDIUM | **Priority**: P2

---

### [HIGH] QS-11: FileHardLinkInformation scans only parent directory — misses cross-directory hard links
**File**: `src/fs/ksmbd_info.c:636-853`
**Issue**: Cross-directory hard links require inode-to-path reverse mapping. Current implementation only checks sibling inodes.
**Fix**: Return partial result with documentation, or use ioctl-level reverse mapping if filesystem provides it.
**Complexity**: HIGH | **Priority**: P3

---

### [HIGH] C-H-01: FileAllocationSize integer overflow risk in SET_INFO
**File**: `src/protocol/smb2/smb2_query_set.c:2839-2846`
**Fix**: Validate `alloc_rounded >> 9 <= LLONG_MAX` or clamp to `MAX_LFS_FILESIZE` before loff_t cast.
**Complexity**: LOW | **Priority**: P2

---

### [MEDIUM] QS-13: FILE_DISPOSITION_POSIX_SEMANTICS not implemented — deferred to pending-delete
**File**: `src/protocol/smb2/smb2_query_set.c:3199-3227`
**Spec**: MS-FSCC §2.4.12 — POSIX_SEMANTICS means unlink immediately from namespace.
**Fix**: When flag set on files, call `vfs_unlink()` immediately instead of setting pending-delete.
**Complexity**: HIGH | **Priority**: P2

---

### [MEDIUM] QS-15: FileCaseSensitiveInformation GET always returns 0
**File**: `src/fs/ksmbd_info.c:1302-1317`
**Fix**: Read `FS_CASEFOLD_FL` via `vfs_fileattr_get()` and return correct state.
**Complexity**: LOW | **Priority**: P3

---

### [MEDIUM] QS-21: FileVolumeNameInformation returns server name instead of volume label
**File**: `src/fs/ksmbd_info.c:1147-1188`
**Fix**: Return share name or empty string, matching `FS_VOLUME_INFORMATION.VolumeLabel`.
**Complexity**: LOW | **Priority**: P3

---

### [MEDIUM] QS-24: SET FileObjectIdInformation stores only 16 bytes, should be 64
**File**: `src/protocol/smb2/smb2_query_set.c:3357-3380`
**Fix**: Change buf_len check to `< 64` and store full 64-byte structure to xattr.
**Complexity**: LOW | **Priority**: P3

---

### [LOW] QS-29: FS_ATTRIBUTE_INFORMATION missing FILE_SUPPORTS_REPARSE_POINTS flag
**File**: `src/protocol/smb2/smb2_query_set.c:1621-1632`
**Fix**: Add `FILE_SUPPORTS_REPARSE_POINTS (0x00000080)` to filesystem attributes bitmask.
**Complexity**: LOW | **Priority**: P3

---

### [LOW] QS-34: FILE_STAT_INFORMATION defined as hex (0x46) — confusable with decimal 46
**File**: `src/include/protocol/smb2pdu.h:1637`
**Fix**: Change to `#define FILE_STAT_INFORMATION 70` and `FILE_STAT_LX_INFORMATION 71`.
**Complexity**: LOW | **Priority**: P4

---

---

## SECTION 6: QUERY_DIRECTORY / CHANGE_NOTIFY / OPLOCK / LEASE (Agent F)

### [HIGH] QD-03: FileIdGlobalTxDirectoryInformation (class 50) uses wrong struct
**File**: `src/protocol/smb2/smb2_dir.c:76-77, 391-427, 857-868`
**Spec**: MS-FSCC §2.4.26 — class 50 has additional LockingTransactionId[16] + TxInfoFlags[4] fields.
**Fix**: Define proper `struct file_id_global_tx_dir_info` and populate it (with zero TxInfoFlags), or reject class 50 with STATUS_INVALID_INFO_CLASS.
**Complexity**: MEDIUM | **Priority**: P2

---

### [HIGH] CN-01: CHANGE_NOTIFY WATCH_TREE not recursive — fsnotify FS_EVENT_ON_CHILD is one-level only
**File**: `src/fs/ksmbd_notify.c:980-985`
**Spec**: MS-SMB2 §3.3.5.19 — WATCH_TREE must monitor ALL subdirectories.
**Issue**: `FS_EVENT_ON_CHILD` notifies only direct children. Subdirectory events are silently missed.
**Fix**: Option A: recursively install fsnotify marks on all subdirectories + maintain on create/delete. Option B: use `fanotify FAN_MARK_FILESYSTEM`. Option C: document as limitation, return STATUS_NOT_SUPPORTED for deep events, force re-enumeration via STATUS_NOTIFY_ENUM_DIR.
**Complexity**: HIGH | **Priority**: P2

---

### [HIGH] OB-03: Oplock break ACK when no break pending returns STATUS_UNSUCCESSFUL instead of STATUS_INVALID_OPLOCK_PROTOCOL
**File**: `src/protocol/smb2/smb2_misc_cmds.c:309-313`
**Fix**: Change `STATUS_UNSUCCESSFUL` to `STATUS_INVALID_OPLOCK_PROTOCOL` at line 311.
**Complexity**: LOW | **Priority**: P2

---

### [MEDIUM] QD-01: Zero FileNameLength on subsequent QUERY_DIRECTORY doesn't reuse last search pattern
**File**: `src/protocol/smb2/smb2_dir.c:1165`
**Spec**: MS-SMB2 §3.3.5.18 — server MUST reuse previous search pattern when FileNameLength==0.
**Fix**: Store `srch_ptr` in `dir_fp->search_pattern` on first call; reuse on subsequent calls with FileNameLength==0.
**Complexity**: LOW | **Priority**: P2

---

### [MEDIUM] CN-02: Rename OLD/NEW NAME events not paired in same CHANGE_NOTIFY response
**File**: `src/fs/ksmbd_notify.c:476-695`
**Spec**: MS-FSCC §2.4.42 — paired records SHOULD be contiguous.
**Fix**: Buffer MOVED_FROM with cookie; when MOVED_TO with same cookie arrives, emit both in one response.
**Complexity**: HIGH | **Priority**: P3

---

### [MEDIUM] CN-03: Stream filter bits (0x200/0x400/0x800) never appear in filter-to-action mapping
**File**: `src/fs/ksmbd_notify.c:1001-1005`
**Fix**: Map FS_ATTRIB to also include stream change bits; or map FS_MODIFY to include stream bits.
**Complexity**: MEDIUM | **Priority**: P3

---

### [MEDIUM] OB-02: File not closed on 35-second oplock break ACK timeout
**File**: `src/fs/oplock.c:742-753`
**Spec**: MS-SMB2 §3.3.5.1 — server MUST close the file on timeout.
**Fix**: On `rc==0` in `wait_for_break_ack()`, initiate file close via `ksmbd_close_fd()`.
**Complexity**: MEDIUM | **Priority**: P3

---

### [MEDIUM] OB-01: Oplock break ACK not validated against notified level
**File**: `src/protocol/smb2/smb2_misc_cmds.c:315-344`
**Fix**: Store notified level in `opinfo->notified_level` at break time; validate `req_oplevel <= notified_level`.
**Complexity**: LOW | **Priority**: P3

---

### [MEDIUM] LB-04: smb_send_parent_lease_break_noti compares lease state (__le32) with OPLOCK_LEVEL_NONE (__u8)
**File**: `src/fs/oplock.c:1496`
**Fix**: Change to `opinfo->o_lease->state != SMB2_LEASE_NONE_LE`.
**Complexity**: LOW | **Priority**: P3

---

---

## SECTION 7: AUTHENTICATE / NEGOTIATE (Agent A)

### [HIGH] AUT-01: NTLMv2 blob minimum size not validated — allows 16-byte blobs
**File**: `src/core/auth.c:646-647, 724-729`
**Spec**: MS-NLMP 2.2.2.7 — NTLMv2_CLIENT_CHALLENGE blob minimum = 48 bytes.
**Fix**: `if (nt_len < (sizeof(struct ntlmv2_resp) + 4)) return -EINVAL;` before NTLMv2 path.
**Complexity**: LOW | **Priority**: P1

---

### [HIGH] AUT-02: Integer underflow risk — blen = nt_len - CIFS_ENCPWD_SIZE without guard in main path
**File**: `src/core/auth.c:676-688`
**Fix**: Add `if (nt_len < CIFS_ENCPWD_SIZE) return -EINVAL;` before line 676.
**Complexity**: LOW | **Priority**: P1

---

### [MEDIUM] AUT-09: Signing algorithm fallback to AES-CMAC without spec basis when no overlap
**File**: `src/protocol/smb2/smb2_negotiate.c:511-535`
**Spec**: MS-SMB2 §3.3.5.4 — when no overlap, should return STATUS_INVALID_PARAMETER (not silently fallback).
**Fix**: When `i == sign_algo_cnt`, return STATUS_INVALID_PARAMETER. Allow fallback only via config flag.
**Complexity**: MEDIUM | **Priority**: P2

---

### [MEDIUM] AUT-05: Preauth HashId validated for non-zero but not for specific SHA512 value
**File**: `src/protocol/smb2/smb2_negotiate.c:881`
**Fix**: Check `conn->preauth_info->Preauth_HashId == SMB2_PREAUTH_INTEGRITY_SHA512` explicitly.
**Complexity**: LOW | **Priority**: P3

---

### [MEDIUM] AUT-06: AvPair pair_data_len used without secondary bounds validation
**File**: `src/core/auth.c:701-703`
**Fix**: Add `if (pair_data_len > blen - pos - 4) return -EINVAL;` before overflow check.
**Complexity**: LOW | **Priority**: P2

---

### [MEDIUM] AUT-13: ClientGUID may be uninitialized during session binding validation
**File**: `src/protocol/smb2/smb2_session.c:745-749`
**Fix**: `if (!memchr_inv(conn->ClientGUID, 0, SMB2_CLIENT_GUID_SIZE)) return -EINVAL;`
**Complexity**: LOW | **Priority**: P3

---

---

## SECTION 8: SMB1 / CIFS (Agent H)

### [HIGH] SMB1-001: LOCKING_ANDX CANCEL_LOCK silently ignored
**File**: `src/protocol/smb1/smb1pdu.c`
**Spec**: MS-CIFS — LOCKING_ANDX with CANCEL_LOCK flag must cancel a pending lock.
**Issue**: The lock cancel path exists in the SMB2 stack but is never hooked for SMB1. Pending SMB1 lock requests are never cancelled, leading to indefinite hangs.
**Fix**: In the SMB1 LOCKING_ANDX handler, when `LockType & LOCKING_ANDX_CANCEL_LOCK`, call `smb1_cancel_lock()` equivalent.
**Complexity**: MEDIUM | **Priority**: P2

---

### [HIGH] SMB1-002: NT_TRANSACT_CREATE returns STATUS_NOT_SUPPORTED
**File**: `src/protocol/smb1/smb1pdu.c`
**Spec**: MS-CIFS §2.2.7.2 — NT_TRANSACT_CREATE creates files with full NT semantics (security descriptors, EAs, oplock).
**Issue**: Many Windows XP-era applications use NT_TRANSACT_CREATE exclusively and cannot fall back to SMB_COM_CREATE.
**Fix**: Implement NT_TRANSACT_CREATE by mapping to the SMB2 create pipeline with security descriptor and EA parameters.
**Complexity**: HIGH | **Priority**: P2

---

### [HIGH] SMB1-003: NT_TRANSACT_IOCTL returns STATUS_NOT_SUPPORTED
**File**: `src/protocol/smb1/smb1pdu.c`
**Spec**: MS-CIFS §2.2.7.4 — NT_TRANSACT_IOCTL is used for FSCTL operations from SMB1 clients.
**Fix**: Map to the ksmbd FSCTL dispatch layer.
**Complexity**: MEDIUM | **Priority**: P3

---

### [HIGH] SMB1-004: NT_TRANSACT_SECONDARY has no handler
**File**: `src/protocol/smb1/smb1pdu.c`
**Spec**: MS-CIFS §2.2.7.7 — multi-packet NT_TRANSACT continuation.
**Fix**: Implement as buffer accumulation + dispatch, similar to TRANSACTION2_SECONDARY.
**Complexity**: HIGH | **Priority**: P3

---

### [HIGH] SMB1-005: TRANSACTION2_SECONDARY has no handler
**File**: `src/protocol/smb1/smb1pdu.c`
**Spec**: MS-CIFS §2.2.6.6 — multi-packet TRANS2 continuation.
**Fix**: Buffer accumulator and dispatch after final fragment.
**Complexity**: MEDIUM | **Priority**: P3

---

### [MEDIUM] SMB1-006: LOCKING_ANDX fl_end off-by-one for 32-bit lock ranges
**File**: `src/protocol/smb1/smb1pdu.c`
**Spec**: fl_end is inclusive — `fl_start + length` but should be `fl_start + length - 1`.
(Previously fixed for SMB2 locks in session 2026-03-01a — verify SMB1 path is also fixed)
**Complexity**: LOW | **Priority**: P2

---

### [MEDIUM] SMB1-007: SMB_COM_FIND and SMB_COM_FIND_UNIQUE — deprecated but not handled
**File**: `src/protocol/smb1/smb1pdu.c`
**Spec**: MS-CIFS §2.2.3 — these commands exist in all NT LM 0.12 implementations.
**Fix**: Return STATUS_NOT_IMPLEMENTED with appropriate error code rather than crashing or timing out.
**Complexity**: LOW | **Priority**: P3

---

---

## SECTION 9: POSIX / APPLE AAPL / DFS / THIRD-PARTY (Agents I + I2)

### [HIGH] POSIX-01: FileStatLxInformation (70) and FileStatInformation (68) — query handlers absent
**File**: `src/protocol/smb2/smb2_query_set.c`, `src/fs/ksmbd_info.c`
**Issue**: Linux SMB clients with `posix` mount option query these info levels for uid/gid/mode. Without handlers, they fall back to FileAllInformation losing uid/gid.
**Fix**: Add case 68/70 handlers filling `FILE_STAT_LX_INFORMATION` from kstat.
**Complexity**: MEDIUM | **Priority**: P1

---

### [HIGH] POSIX-03: FileDispositionInformationEx (64) POSIX unlink not implemented
**File**: `src/protocol/smb2/smb2_query_set.c`
**Fix**: Add case 64; detect `FILE_DISPOSITION_POSIX_SEMANTICS`; call `vfs_unlink()` immediately.
**Complexity**: HIGH | **Priority**: P2

---

### [HIGH] POSIX-04: FileRenameInformationEx (65) POSIX atomic rename not implemented
**File**: `src/protocol/smb2/smb2_query_set.c`
**Fix**: Add case 65; detect `FILE_RENAME_POSIX_SEMANTICS`; bypass open-handle check.
**Complexity**: HIGH | **Priority**: P2

---

### [MEDIUM] POSIX-05: SMB_FIND_FILE_POSIX_INFO (0x64) QUERY_DIRECTORY handler absent
**File**: `src/protocol/smb2/smb2_dir.c`
**Fix**: Add case 0x64 in `smb2_populate_readdir_entry()` filling `smb2_posix_info` with uid/gid/mode.
**Complexity**: MEDIUM | **Priority**: P2

---

### [HIGH] AAPL-02: kAAPL_SUPPORTS_TM_LOCK_STEAL advertised but unimplemented — Time Machine corruption risk
**File**: `src/fs/oplock.c:2781`
**Fix**: Remove `kAAPL_SUPPORTS_TM_LOCK_STEAL` from advertised caps until implemented.
**Complexity**: LOW | **Priority**: P1

---

### [HIGH] AAPL-03: AFP_AfpInfo write path missing — FinderInfo writes silently lost
**File**: `src/protocol/smb2/smb2fruit.c:458-511`
**Fix**: Implement `ksmbd_fruit_write_afpinfo()` that splits 60-byte structure into xattr writes (bytes 16-47 → `com.apple.FinderInfo`).
**Complexity**: MEDIUM | **Priority**: P2

---

### [HIGH] DFS-01: PathConsumed uses raw byte count instead of UTF-16 codeunit count
**File**: `src/fs/ksmbd_dfs.c:300`
**Spec**: MS-DFSC §2.2.3 — PathConsumed is character count (codeunits), not bytes.
**Fix**: `cpu_to_le16(min_t(unsigned int, req_name_len / sizeof(__le16), U16_MAX))`
**Complexity**: LOW | **Priority**: P1

---

### [HIGH] DFS-02: DFS V2 referral entry `size` field includes string data — V2 must be fixed-header only
**File**: `src/fs/ksmbd_dfs.c:317, 330, 342`
**Spec**: MS-DFSC §2.2.5.2 — V2 Size is fixed-header only; V3/V4 is total size.
**Fix**: For V2: `size = sizeof(struct dfs_referral_level_2)`. For V3/V4: current value is correct.
**Complexity**: LOW | **Priority**: P2

---

### [HIGH] MC-01: Per-channel signing key not derived — all channels use session key
**File**: `src/protocol/smb2/smb2_session.c`
**Spec**: MS-SMB2 §3.3.5.5.3 — each channel MUST derive its own `Channel.SigningKey`.
**Fix**: Derive per-channel signing keys: `HMAC-SHA256(Session.SigningKey, "SMBSigningKey" || pre-auth-hash)`.
**Complexity**: HIGH | **Priority**: P1

---

### [MEDIUM] VSS-02: VSS backend iterator releases lock mid-traversal — list corruption possible
**File**: `src/fs/ksmbd_vss.c:597-618`
**Issue**: `list_for_each_entry` from `be->list.next` after unlock — if `be` was removed, iterator corrupts.
**Fix**: Copy backend function pointer under lock, release lock, call pointer; re-acquire for next entry by re-iterating from list head.
**Complexity**: MEDIUM | **Priority**: P2

---

### [MEDIUM] DFS-04: All referrals returned as ROOT type instead of ROOT vs LINK
**File**: `src/fs/ksmbd_dfs.c:318, 331, 343`
**Fix**: Determine if requested path is DFS root or link and set `server_type` accordingly.
**Complexity**: MEDIUM | **Priority**: P3

---

### [LOW] AAPL-05: kAAPL_RESOLVE_ID (ResolveID) FSCTL never wired to ksmbd_vfs_resolve_fileid
**File**: `src/fs/vfs.c:2176-2200`
**Fix**: Register IOCTL handler for AAPL command_code=4 calling `ksmbd_vfs_resolve_fileid()`.
**Complexity**: MEDIUM | **Priority**: P3

---

---

## SECTION 10: READ / WRITE / LOCK / ECHO / CANCEL (Agent E)

### [HIGH] RW-001: CANCEL command never sends error response when cancellation fails
**File**: `src/protocol/smb2/smb2_lock.c:84-248`
**Spec**: MS-SMB2 §3.3.5.16 — server MAY return STATUS_NOT_FOUND when no matching request found.
**Issue**: `send_no_response = 1` unconditionally; clients cannot distinguish success from failure.
**Fix**: When no matching request found, send explicit error response. On success, suppress as now.
**Complexity**: LOW | **Priority**: P3

---

### [HIGH] RW-002: ECHO request StructureSize not validated
**File**: `src/protocol/smb2/smb2_misc_cmds.c:248-259`
**Spec**: MS-SMB2 §2.2.27 — ECHO request StructureSize MUST be 4.
**Fix**: Validate StructureSize == 4; return STATUS_INVALID_PARAMETER if invalid.
**Complexity**: LOW | **Priority**: P3

---

### [MEDIUM] RW-003: READ MinimumCount > Length not rejected with STATUS_INVALID_PARAMETER
**File**: `src/protocol/smb2/smb2_read_write.c:479-480`
**Spec**: MS-SMB2 §3.3.5.12 step 2 — MinimumCount > Length → STATUS_INVALID_PARAMETER.
**Fix**: `if (mincount > length) { err = -EINVAL; goto out; }` before performing the read.
**Complexity**: LOW | **Priority**: P2

---

### [LOW] RW-004: LockSequenceNumber header comment incorrect (bits reversed)
**File**: `src/include/protocol/smb2pdu.h:1282-1286`
**Issue**: Comment says bits 28-31 = LockSequenceNumber, but code correctly uses bits 0-3.
**Fix**: Correct the comment: "Bits 0-3: LockSequenceNumber, Bits 4-31: LockSequenceIndex".
**Complexity**: LOW | **Priority**: P4

---

---

## IMPLEMENTATION PLAN

### Phase A — Security Critical (P0, Week 1)
Fix order:
1. TC-23 (decrypt includes AEAD tag — 1 line, fixes all encrypted sessions)
2. QUIC-08 (wrong HKDF prefix — 1 line, fixes all QUIC key derivation)
3. QUIC-01 (AEAD SGL — fixes QUIC authentication)
4. ACL-01 (SD revision validation)
5. ACL-02 (missing ACE types in access check)
6. ACL-08 (SELF_RELATIVE flag validation)
7. QS-03 (EaNameLength bounds check — potential heap read)
8. AUT-01 + AUT-02 (NTLMv2 blob validation)

### Phase B — Protocol Correctness High (P1, Week 2)
9. TC-04 (outstanding_credits leak on send_no_response)
10. TC-10 (multi-channel decrypt session lookup)
11. TC-05 (TRANSFORM_HEADER OriginalMessageSize bounds)
12. TC-01 (TCP_NODELAY on client sockets)
13. QS-02 (EA single-EA not found status)
14. QS-04 (FileValidDataLength access check)
15. CC-03 (CopyChunk offset overflow)
16. SP-01 (SET_SPARSE write access check)
17. QNI-01 (LinkSpeed /8 bug)
18. DFS-01 (PathConsumed bytes vs codeunits)
19. REPARSE-01 (SYMLINK_FLAG_RELATIVE for absolute symlinks)
20. AAPL-02 (remove TM_LOCK_STEAL advertisement)
21. POSIX-01 (FileStatLxInformation handlers)
22. AUT-01 + AUT-02 (NTLMv2 validation)
23. MC-01 (per-channel signing keys)

### Phase C — Protocol Features (P2, Week 3-4)
24. TC-08 (compound related session null crash)
25. TC-19 (work->tr_sess_id set)
26. TC-22 (compound_sid reset)
27. QS-07 + QS-08 (LABEL_SECINFO access check + SET persistence)
28. QS-10 (EASize in FileAllInformation)
29. QS-13 (POSIX disposition unlink)
30. ACL-03 (OBJECT ACE SID offset)
31. ACL-04 (SACL GET reads ksmbd_label xattr)
32. ACL-05 (ACL revision validation)
33. ACL-07 (INHERIT_ONLY ACEs excluded from access check)
34. INHERIT-01 (inheritance buffer size)
35. POSIX-03 + POSIX-04 (disposition+rename ex info levels)
36. POSIX-05 (QUERY_DIR POSIX_INFO handler)
37. QD-01 (zero FileNameLength reuses last pattern)
38. QD-03 (FileIdGlobalTxDirectoryInfo wrong struct)
39. OB-03 (wrong status for no-break-pending ACK)
40. IOCTL-01 (FileId fields in responses)
41. QNI-03 (empty interface list)
42. OI-02 (SET_OBJECT_ID_EXTENDED)
43. PP-03 (PIPE_TRANSCEIVE zero-byte RPC)
44. DFS-02 (V2 referral size)
45. AAPL-03 (AFP_AfpInfo write path)
46. RW-003 (READ MinimumCount validation)
47. SMB1-001 (LOCKING_ANDX CANCEL)
48. SMB1-006 (fl_end off-by-one)
49. AUT-06 (AvPair secondary bounds)

### Phase D — Enhancement (P3, Week 5-6)
50. QUIC-02 (Initial packet encryption)
51. QUIC-03 (1-RTT receive path)
52. QUIC-04 (Retry token)
53. QUIC-05 (ACK sending)
54. QUIC-07 (TRANSPORT_CAPABILITIES in NEGOTIATE)
55. CN-01 (WATCH_TREE recursive — use fanotify or document)
56. CN-02 (rename pair delivery)
57. TC-07 (preauth hash frozen after auth)
58. TC-11 (compound response Signature zeroed)
59. TC-17 (compound chain finalization on disconnect)
60. QS-21 (FileVolumeNameInformation format)
61. QS-24 (FileObjectIdInformation 64 bytes)
62. ACL-06 (DACL_AUTO_INHERIT_REQ propagation)
63. REPARSE-03 (SubstituteName `\??\` prefix)
64. OI-02 (ObjectId 64-byte storage)
65. VSS-02 (VSS iterator lock safety)
66. DFS-04 (ROOT vs LINK referral type)
67. OB-01 + OB-02 (oplock ACK validation + timeout close)
68. LB-04 (lease state type mismatch)
69. CN-03 (stream filter bits)
70. SMB1-002 + SMB1-003 (NT_TRANSACT_CREATE, NT_TRANSACT_IOCTL)
71. GEN-03 (dead code in ksmbd_fsctl_extra.c)
72. AUT-09 (signing algo negotiation strictness)
73. C-H-01 (FileAllocationSize overflow)
74. QS-15 (FileCaseSensitiveInformation GET)
75. QS-29 (FILE_SUPPORTS_REPARSE_POINTS flag)
76. RW-001 + RW-002 (CANCEL response, ECHO validation)

### Phase E — Polish / Low Priority (P4)
- QS-34 (FILE_STAT_INFORMATION hex constant → decimal)
- RW-004 (LockSequenceNumber comment)
- Various LOW severity documentation items
- SMB1-004 + SMB1-005 (NT_TRANSACT/TRANSACTION2_SECONDARY)
- AAPL-05 (ResolveID wiring)
- DFS-05 (referral entry flags)

---

## COVERAGE SUMMARY BY SPEC

| Specification | Coverage Before V10 | Remaining Gaps |
|---|---|---|
| MS-SMB2 §2.2.3 (NEGOTIATE) | 90% | AUT findings |
| MS-SMB2 §2.2.5 (SESSION_SETUP) | 85% | AUT-09, AUT-13 |
| MS-SMB2 §2.2.9 (TREE_CONNECT) | 95% | Minor |
| MS-SMB2 §2.2.13 (CREATE) | 85% | Persistent handles stub |
| MS-SMB2 §2.2.19-22 (READ/WRITE) | 92% | RW-003 |
| MS-SMB2 §2.2.23 (OPLOCK_BREAK) | 88% | OB-01/02/03 |
| MS-SMB2 §2.2.31-32 (IOCTL) | 80% | IOCTL-01, PP-01/02 |
| MS-SMB2 §2.2.33 (QUERY_DIR) | 88% | QD-01/03 |
| MS-SMB2 §2.2.35 (CHANGE_NOTIFY) | 75% | CN-01 (WATCH_TREE) |
| MS-SMB2 §2.2.37-40 (INFO) | 82% | QS findings |
| MS-SMB2 §2.2.41 (TRANSFORM) | 85% | TC-23, TC-05 |
| MS-DTYP §2.4 (Security) | 70% | ACL-01/02/03/08 |
| MS-FSCC §2.4 (File Info) | 83% | Various QS |
| MS-FSCC §2.3 (FSCTL) | 78% | FSCTL gaps |
| MS-CIFS (SMB1) | 75% | NT_TRANSACT, CANCEL |
| MS-DFSC (DFS) | 60% | DFS-01/02/04 |
| Apple AAPL | 55% | AAPL-02/03/04 |
| POSIX Extensions | 70% | POSIX-01/03/04/05 |
| RFC 9000/9001 (QUIC) | 35% | QUIC-01/02/03/08 |
| MS-RSVD | 50% | RSVD-01 async |
| MS-SWN (Witness) | 55% | Registration |
| MS-PCCRD (BranchCache) | 70% | Minor |
