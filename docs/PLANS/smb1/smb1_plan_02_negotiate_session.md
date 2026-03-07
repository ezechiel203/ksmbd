# SMB1 Upgrade Plan — Section 02: Negotiate & Session Management Commands

**Scope:** MS-SMB compliance for `SMB_COM_NEGOTIATE` (0x72), `SMB_COM_SESSION_SETUP_ANDX` (0x73), `SMB_COM_TREE_CONNECT_ANDX` (0x75), `SMB_COM_LOGOFF_ANDX` (0x74), and `SMB_COM_TREE_DISCONNECT` (0x71).

**Primary source files examined:**
- `src/protocol/smb1/smb1pdu.c` — command handlers
- `src/protocol/smb1/smb1misc.c` — message validation
- `src/protocol/smb1/smb1ops.c` — dispatch table and version values
- `src/protocol/common/smb_common.c` — dialect negotiation, common negotiate path
- `src/include/protocol/smb1pdu.h` — PDU structures and constants

---

## 1. SMB_COM_NEGOTIATE (0x72)

### MS-SMB Reference
MS-SMB §2.2.4.52 — SMB_COM_NEGOTIATE Request/Response.

### 1.1 Request Parsing

#### Required Request Fields (§2.2.4.52.1)
| Field | Type | Description |
|---|---|---|
| WordCount | UCHAR | Must be 0x00 |
| ByteCount | USHORT | Total bytes in DialectsArray |
| DialectsArray | variable | NUL-terminated dialect strings, each preceded by 0x02 |

**KSMBD status:** Correct. `smb1misc.c` `smb1_req_struct_size()` enforces `WordCount == 0`. `smb1_get_byte_count()` enforces `ByteCount >= 2`. `next_dialect()` iterates the packed 0x02-prefixed string list safely. The size cross-check in `ksmbd_negotiate_smb_dialect()` guards against truncated packets.

**Issue — Dialect comparison strips 0x02 prefix inconsistently:** The `smb1_protos[]` table stores dialect strings with the 0x02 byte embedded (e.g., `"\2NT LM 0.12"`), while `next_dialect()` advances past the 0x02 byte and returns a pointer to the plain text. The comparison at line 273–275 of `smb_common.c` compares the returned plain-text pointer against `smb1_protos[i].name` which also includes the 0x02 prefix. **This comparison is always false for `NT LM 0.12`** because `strcmp("\2NT LM 0.12", "NT LM 0.12")` is non-zero. The only reason this works at all is the fallback alias `"\2NT LANMAN 1.0"` check, and the fact that `next_dialect()` actually does return the dialect **including** its 0x02 byte (it sets `*next_off = strnlen(dialect, bcount)` then compares `dialect[*next_off] != '\0'` — so the 0x02 byte is part of the string passed to the caller). **Verification of this requires tracing the pointer arithmetic through `next_dialect()` carefully**, but any mismatch here would cause spurious `BAD_PROT_ID` results.

**Fix needed:** Audit the exact pointer arithmetic in `next_dialect()` and the comparison in `ksmbd_lookup_dialect_by_name()`. The 0x02 prefix byte must either always be included in the comparison value or always stripped. Per MS-SMB §2.2.4.52.1, the 0x02 byte is a buffer format byte that precedes each dialect string; the dialect names themselves do not include it.

---

### 1.2 Response — NT LM 0.12 (Extended Security path)

#### Required Response Fields (§2.2.4.52.2, NT LM 0.12 with CAP_EXTENDED_SECURITY)
| Field | Type | Set by KSMBD | Notes |
|---|---|---|---|
| WordCount | UCHAR | 17 | Correct (line 997) |
| DialectIndex | USHORT | `conn->dialect` | Correct |
| SecurityMode | UCHAR | `SECMODE_USER | SECMODE_PW_ENCRYPT` | Correct; signing bits conditionally set |
| MaxMpxCount | USHORT | 10 (`SMB1_MAX_MPX_COUNT`) | Correct |
| MaxNumberVcs | USHORT | 1 (`SMB1_MAX_VCS`) | Correct |
| MaxBufferSize | ULONG | `conn->vals->max_read_size` | **Issue — see §1.2.1** |
| MaxRawSize | ULONG | 65536 (`SMB1_MAX_RAW_SIZE`) | **Issue — see §1.2.2** |
| SessionKey | ULONG | 0 | **Issue — see §1.2.3** |
| Capabilities | ULONG | `SMB1_SERVER_CAPS` | **Issue — see §1.2.4** |
| SystemTimeLow | ULONG | `ksmbd_systime() & 0xFFFFFFFF` | Correct |
| SystemTimeHigh | ULONG | `ksmbd_systime() >> 32` | Correct |
| ServerTimeZone | SHORT | 0 | **Issue — see §1.2.5** |
| EncryptionKeyLength | UCHAR | 0 (extended) / 8 (classic) | Correct |
| ByteCount | USHORT | 16 + spnego_len | Correct |
| GUID[16] | UCHAR[16] | random bytes | Correct per spec |
| SecurityBlob | variable | SPNEGO negTokenInit | Correct |

##### 1.2.1 MaxBufferSize Compliance Issue (§2.2.4.52.2)
The spec defines `MaxBufferSize` as the maximum size of a non-raw write in bytes. KSMBD sets it to `conn->vals->max_read_size` which is `CIFS_DEFAULT_IOSIZE` (65536). Per MS-SMB, `MaxBufferSize` must be at minimum 1024 bytes and should not exceed 65535 for SMB1 clients that may enforce 16-bit arithmetic. Setting it to 65536 (0x00010000) is technically legal for NT LM 0.12 but some legacy clients (pre-NT) cap at 0xFFFF. More importantly, `MaxBufferSize` is also used by clients as the receive buffer allocation limit for the connection — it should match `MaxRawSize` or be at least as large. No functional bug here but document the intent.

##### 1.2.2 MaxRawSize (§2.2.4.52.2)
`MaxRawSize` is valid only when `CAP_RAW_MODE` is advertised. KSMBD advertises `MaxRawSize = 65536` but does **not** include `CAP_RAW_MODE` in `SMB1_SERVER_CAPS` (defined in `smb1pdu.h`). Per MS-SMB §2.2.4.52.2: "If CAP_RAW_MODE is not set in Capabilities, MaxRawSize SHOULD be set to 0." **Fix required:** Set `MaxRawSize = 0` when not advertising `CAP_RAW_MODE`.

##### 1.2.3 SessionKey (§2.2.4.52.2)
Per MS-SMB §2.2.4.52.2, `SessionKey` is an opaque value used by the client to match session setup requests to the correct negotiate response. KSMBD always sets it to 0. This is allowed by the spec ("The Server can set this to any value") but limits multi-VC scenarios. No mandatory fix; document as known limitation.

##### 1.2.4 Capabilities Bit Audit (§2.2.4.52.2)
Current `SMB1_SERVER_CAPS` (from `smb1pdu.h`):
```c
CAP_UNICODE | CAP_LARGE_FILES | CAP_EXTENDED_SECURITY |
CAP_NT_SMBS | CAP_STATUS32 | CAP_NT_FIND |
CAP_UNIX | CAP_LARGE_READ_X | CAP_LARGE_WRITE_X | CAP_LEVEL_II_OPLOCKS
```

**Missing or incorrect capability bits:**

| Capability | Value | Status | Notes |
|---|---|---|---|
| `CAP_RAW_MODE` | 0x0001 | Absent (correct) | No raw-mode handler |
| `CAP_MPX_MODE` | 0x0002 | Absent | **Issue:** KSMBD supports multiplexing (MaxMpxCount=10). Must advertise if supporting multiple in-flight requests. |
| `CAP_UNICODE` | 0x0004 | Present | Correct |
| `CAP_LARGE_FILES` | 0x0008 | Present | Correct |
| `CAP_NT_SMBS` | 0x0010 | Present | Correct |
| `CAP_RPC_REMOTE_APIS` | 0x0020 | Absent | **Issue:** IPC$ named pipe RPC is implemented. Should be advertised per MS-SMB §2.2.4.52.2. |
| `CAP_STATUS32` | 0x0040 | Present | Correct |
| `CAP_LEVEL_II_OPLOCKS` | 0x0080 | Present | Correct |
| `CAP_LOCK_AND_READ` | 0x0100 | Absent (correct) | No handler for opcode 0x13; correctly omitted per existing comment |
| `CAP_NT_FIND` | 0x0200 | Present | Correct |
| `CAP_DFS` | 0x1000 | Absent | **Issue:** DFS referral support exists (`ksmbd_dfs.c`). If DFS is enabled, this bit must be set and `SMBFLG2_DFS` set in header Flags2. |
| `CAP_INFOLEVEL_PASSTHRU` | 0x2000 | Absent | **Issue:** TRANS2 info-level passthrough is implemented. Should be advertised. |
| `CAP_LARGE_READ_X` | 0x4000 | Present | Correct |
| `CAP_LARGE_WRITE_X` | 0x8000 | Present | Correct |
| `CAP_LWIO` | 0x00010000 | Absent | Low-priority; FSCTL_SRV_REQUEST_RESUME_KEY not fully implemented |
| `CAP_UNIX` | 0x00800000 | Present | Correct for POSIX extensions |
| `CAP_COMPRESSED_DATA` | 0x02000000 | Absent | Correct — SMB1 compression not implemented |
| `CAP_DYNAMIC_REAUTH` | 0x20000000 | Absent | Correct — not implemented |
| `CAP_PERSISTENT_HANDLES` | 0x40000000 | Absent | Correct — SMB1 has no persistent handles |
| `CAP_EXTENDED_SECURITY` | 0x80000000 | Present | Correct |

**Required fixes:**
1. Add `CAP_MPX_MODE` when `MaxMpxCount > 1` (MS-SMB §2.2.4.52.2 normative requirement).
2. Add `CAP_RPC_REMOTE_APIS` to signal named-pipe DCE/RPC support.
3. Add `CAP_INFOLEVEL_PASSTHRU` since TRANS2 passthrough info levels are handled.
4. Add `CAP_DFS` conditionally when DFS is configured.

##### 1.2.5 ServerTimeZone (§2.2.4.52.2)
Per MS-SMB §2.2.4.52.2, `ServerTimeZone` is the current offset in minutes from UTC of the server's local time. KSMBD sets it to 0 (UTC). This is technically valid if the server operates in UTC, but for deployments in non-UTC timezones, timestamps on files may appear shifted to clients that use `ServerTimeZone` for correction. **Fix (optional/low-priority):** Expose a configuration option, or read the kernel's UTC offset.

---

### 1.3 Response — Non-Extended Security Path (classic challenge/response)

#### Required fields (§2.2.4.52.2, CAP_EXTENDED_SECURITY not set)
| Field | Notes |
|---|---|
| EncryptionKeyLength | 8 (`CIFS_CRYPTO_KEY_SIZE`) |
| EncryptionKey[8] | 8-byte server challenge |
| DomainName | OEM/Unicode NUL-terminated server domain |

**KSMBD status:**
- Encryption key (challenge): Correct — `get_random_bytes()` fills `conn->ntlmssp.cryptkey` (line 1031).
- `EncryptionKeyLength = CIFS_CRYPTO_KEY_SIZE` (8): Correct.
- **DomainName: Missing.** After the 8-byte `EncryptionKey`, the spec requires a NUL-terminated OEM string (or Unicode if `CAP_UNICODE` was in the request) for `DomainName`. The existing code has a comment "Null terminated domain name in unicode" at line 1047 but does **not actually write the domain name to the wire**. The `ByteCount` is set to `CIFS_CRYPTO_KEY_SIZE` (8) only, omitting the domain name. Per MS-SMB §2.2.4.52.2: "DomainName (variable): The domain or workgroup of the server." **Fix required:** Append `server_conf.work_group` as a NUL-terminated OEM string (or UTF-16LE when CAP_UNICODE) after the challenge bytes. Update `ByteCount` accordingly. This is a spec violation that may cause authentication failures with strict clients.

---

### 1.4 Pre-NT Dialect Responses (LANMAN1.0, LM1.2X002, etc.)

#### Spec requirement (§2.2.4.52.2, PC NETWORK PROGRAM 1.0 / LANMAN1.0)
Pre-NT dialect negotiate responses have a **completely different wire format** from NT LM 0.12:

**PC NETWORK PROGRAM 1.0 response (WordCount = 1):**
```
DialectIndex  USHORT
```
No security parameters; purely selects a dialect. ByteCount = 0.

**LANMAN1.0 / LM1.2X002 / LANMAN2.1 response (WordCount = 13):**
```
DialectIndex       USHORT
SecurityMode       USHORT  (2-byte, not 1-byte)
MaxBufferSize      USHORT
MaxMpxCount        USHORT
MaxNumberVcs       USHORT
RawMode            USHORT
SessionKey         ULONG
ServerTime         USHORT
ServerDate         USHORT
ServerTimeZone     SHORT
EncryptionKeyLength USHORT
Reserved           USHORT
ByteCount          USHORT
EncryptionKey      variable (length from EncryptionKeyLength)
PrimaryDomain      variable (NUL-terminated OEM)
```
Note: `SecurityMode` is 2 bytes wide (not 1 byte), and the bit meanings differ from NT LM 0.12.

**KSMBD status:** KSMBD **only implements the NT LM 0.12 (WordCount=17) response** in `smb_handle_negotiate()`. The `smb1_protos[]` array contains only `NT LM 0.12` as the sole SMB1 dialect. If a client offers only pre-NT dialects (LANMAN1.0, LANMAN2.1, LM1.2X002, etc.) without `NT LM 0.12`, the `ksmbd_lookup_dialect_by_name()` function returns `BAD_PROT_ID`, and `smb_handle_negotiate()` returns `STATUS_INVALID_LOGON_TYPE`.

**Assessment:** Per the KSMBD design goal (NT LM 0.12 minimum), rejecting pre-NT clients is intentional and documented. However, MS-SMB full compliance requires also handling these older formats correctly. The following two sub-issues remain:

1. **Wrong error code for unacceptable dialect:** MS-SMB §2.2.4.52.2 specifies that when no dialect is acceptable, `DialectIndex` should be set to `0xFFFF` with `Status = STATUS_SUCCESS` (the error is conveyed in `DialectIndex`, not in the status field). KSMBD returns `STATUS_INVALID_LOGON_TYPE` which is a non-standard error for this situation. **Fix:** On `BAD_PROT_ID`, return `WordCount=1, DialectIndex=0xFFFF, ByteCount=0, Status=STATUS_SUCCESS`. This is what Windows Server sends when no mutually supported dialect exists.

2. **`PC NETWORK PROGRAM 1.0` response format:** If support for pure pre-NT clients is ever added, a separate response-building path is required because the wire format is structurally different (different WordCount, different SecurityMode width, USHORT-based time fields, no Capabilities).

---

### 1.5 Security Implications

- Not advertising `CAP_RPC_REMOTE_APIS` correctly may cause DCE/RPC operations to fail on some clients.
- Sending `STATUS_INVALID_LOGON_TYPE` instead of `DialectIndex=0xFFFF` for unsupported dialects leaks server capability information unnecessarily and is not spec-compliant.
- The missing DomainName in the non-extended-security response may cause legacy NTLM clients to skip domain-based account selection, potentially authenticating to a wrong account.
- The SPNEGO path correctly uses randomized GUIDs for negotiate, which is good for security.

---

## 2. SMB_COM_SESSION_SETUP_ANDX (0x73)

### MS-SMB Reference
MS-SMB §2.2.4.53 — SMB_COM_SESSION_SETUP_ANDX Request/Response.

### 2.1 Request Format Variants

The spec defines three request formats based on `WordCount` and client capabilities:

| Variant | WC | When Used |
|---|---|---|
| NT LM 0.12 w/ Extended Security | 12 | Client sets `CAP_EXTENDED_SECURITY` in Capabilities |
| NT LM 0.12 No Extended Security | 13 | NT dialect, no SPNEGO |
| LM 2.1 / Old-style | varies | Pre-NT clients |

**KSMBD status:** Handled correctly for WC=12 and WC=13 in `smb_session_setup_andx()` at line 1391–1395. The `union smb_com_session_setup_andx` discriminates on `WordCount`. Any other WordCount causes `work->send_no_response = 1` and returns. **Issue:** Per MS-SMB §2.2.4.53.1, the correct response to an invalid `WordCount` is `STATUS_INVALID_PARAMETER`, not a silent drop. The current `send_no_response = 1` approach violates the spec's requirement to always respond.

### 2.2 NT LM 0.12 No Extended Security (WordCount=13)

#### Request Fields (§2.2.4.53.1, NT LM 0.12, CAP_EXTENDED_SECURITY not set)
| Field | Handled | Notes |
|---|---|---|
| MaxBufferSize | No | Client's max buffer size — KSMBD ignores this |
| MaxMpxCount | No | Client's max multiplexed requests — KSMBD ignores this |
| VcNumber | No | Virtual circuit number — KSMBD ignores this |
| SessionKey | No | Must match server's SessionKey from NEGOTIATE — KSMBD ignores this |
| CaseInsensitivePasswordLength | Yes | Used to find OEM hash |
| CaseSensitivePasswordLength | Yes | Used to find Unicode/NTLMv2 hash |
| Capabilities | Yes | Checked for `CAP_EXTENDED_SECURITY` |
| Account (username) | Yes | Parsed after passwords |
| PrimaryDomain | Yes | Read for NTLMv2 |
| NativeOS | No | Not validated or stored |
| NativeLanMan | No | Not validated or stored |

**Issues:**

1. **VcNumber not handled (§2.2.4.53.1):** Per MS-SMB §2.2.4.53.1, if `VcNumber == 0`, the server SHOULD close all existing virtual circuits for the client before creating the new session. If `VcNumber > 0`, the new session is an additional VC. KSMBD does not implement this logic at all. **Fix required:** When `VcNumber == 0`, call `ksmbd_destroy_conn_sessions()` or equivalent before creating the new session, to comply with spec-mandated reconnect behavior.

2. **SessionKey not validated (§2.2.4.53.1):** The spec allows the server to validate that the client's `SessionKey` matches the one sent in the NEGOTIATE response. KSMBD sets `SessionKey = 0` in negotiate and ignores it in session setup — this is consistent and safe, but document it.

3. **Alignment/padding in no-secext variant (line 1079):** The code uses a hard-coded `+ 1` byte padding offset to skip to the account name. Per MS-SMB §2.2.4.53.1, if the dialect is NT LM 0.12 and `CAP_UNICODE` is in the request header `Flags2`, strings that follow the password blobs may be aligned to a 2-byte boundary. The padding behavior depends on whether the password fields end on an even offset. **Issue:** The code adds `+ 1` unconditionally (line 1079 in `build_sess_rsp_noextsec()`). This is not robust — if the combined password length is already even, the skip should be 0 bytes, not 1. **Fix:** Compute alignment dynamically: `pad = (2 - ((sizeof(struct smb_hdr) + fixed_wc_sz + pw_lengths) & 1)) & 1` when the client requested Unicode.

4. **NTLMv1/LM response authentication path (§2.2.4.53.1):** The spec specifies a separate LM response (8 bytes) and NTLM response (24 bytes). KSMBD's `build_sess_rsp_noextsec()` checks `CaseSensitivePasswordLength == CIFS_AUTH_RESP_SIZE` (24) to select NTLM. When `CaseInsensitivePasswordLength > 0` and `CaseSensitivePasswordLength < CIFS_AUTH_RESP_SIZE`, KSMBD falls through to an NTLMv2 path. **Issue:** An LM-only authentication (CaseSensitivePasswordLength = 0, CaseInsensitivePasswordLength = 24) is not handled and will fall to the NTLMv2 path which will fail. This is a corner case (LM-only clients are ancient), but per MS-SMB it must return a proper error rather than mis-routing.

### 2.3 NT LM 0.12 with Extended Security (WordCount=12, SPNEGO)

#### Request Fields (§2.2.4.53.1, Extended Security)
| Field | Handled | Notes |
|---|---|---|
| SecurityBlobLength | Yes | Used to bound blob parsing |
| SecurityBlob | Yes | SPNEGO negToken parsed in `build_sess_rsp_extsec()` |
| NativeOS | No | Ignored |
| NativeLanMan | No | Ignored |

**Issues:**

1. **`SecurityBlobLength` passed as static length in authentication decode:** At line 1326 of `build_sess_rsp_extsec()`, `ksmbd_decode_ntlmssp_auth_blob()` is called with `le16_to_cpu(req->SecurityBlobLength)` as the blob length, but when `conn->mechToken` is set (SPNEGO decoding extracted an inner NTLMSSP token), the actual length of `authblob` comes from the mechToken size, not `SecurityBlobLength`. Passing the outer SPNEGO SecurityBlobLength as the NTLMSSP blob length can cause the NTLMSSP parser to read beyond the actual inner token. **Fix required:** When `conn->mechToken` is set, track and use `conn->mechTokenLen` rather than `req->SecurityBlobLength`.

2. **No `NativeOS`/`NativeLanMan` recorded:** MS-SMB §2.2.4.53.1 does not strictly require storing these, but for logging and compatibility determination they are useful. Low priority.

3. **`STATUS_MORE_PROCESSING_REQUIRED` path:** Correctly set (line 1279) for the NTLMSSP challenge phase. Correct.

### 2.4 Response Format

#### NT LM 0.12 Extended Security Response (§2.2.4.53.2, WordCount=4)
| Field | KSMBD Status | Notes |
|---|---|---|
| WordCount=4 | Correct | Line 1195 |
| AndXCommand | Correct | |
| AndXReserved | Correct | |
| AndXOffset | Correct | |
| Action | Correct | `GUEST_LOGIN` bit set for guests |
| SecurityBlobLength | Correct | |
| ByteCount | Correct | |
| SecurityBlob | Correct | SPNEGO token |
| NativeOS | **Missing** | See §2.4.1 |
| NativeLanMan | **Missing** | See §2.4.1 |
| PrimaryDomain | **Missing** | See §2.4.1 |

##### 2.4.1 Missing NativeOS, NativeLanMan, PrimaryDomain in Extended Security Response
Per MS-SMB §2.2.4.53.2: "NativeOS ... NativeLanMan ... PrimaryDomain" must be appended after the SecurityBlob in the ByteCount data area. The `build_sess_rsp_extsec()` function does **not** append these strings. They are included in the no-extsc response (`build_sess_rsp_noextsec()` writes NativeOS, LanMan name, and workgroup as Unicode strings at lines 1154–1167), but are absent from the extended security response path.

**Fix required:** After writing the SecurityBlob in `build_sess_rsp_extsec()` (both for the challenge phase STATUS_MORE_PROCESSING_REQUIRED and the final success), append:
- NativeOS as `"Windows"` or equivalent (UTF-16LE NUL-terminated, with 1-byte pad if needed for alignment)
- NativeLanMan (server's LAN Manager version string)
- PrimaryDomain (from `server_conf.work_group`, UTF-16LE NUL-terminated)

Update `ByteCount` and `inc_rfc1001_len` accordingly.

**Note:** Some Windows clients, especially older Windows XP and Windows 2000 clients, examine `PrimaryDomain` from the session setup response for domain account routing and credential caching. Its absence may cause authentication anomalies.

#### NT LM 0.12 No Extended Security Response (§2.2.4.53.2, WordCount=3)
| Field | KSMBD Status | Notes |
|---|---|---|
| WordCount=3 | Correct | Line 1067 |
| Action | Correct | Guest bit |
| ByteCount | Correct | |
| NativeOS | Correct | "Unix" (UTF-16LE) |
| NativeLanMan | Correct | "ksmbd" (UTF-16LE) |
| PrimaryDomain | Present | "WORKGROUP" hard-coded |

**Issue:** PrimaryDomain is hard-coded to "WORKGROUP" (line 1164) instead of using `server_conf.work_group`. **Fix:** Replace with `server_conf.work_group`.

### 2.5 Guest and Null Session Handling

#### Guest (§2.2.4.53.2 Action bit 0)
`GUEST_LOGIN` (0x0001) is set in `Action` when `user_guest(sess->user)` is true. **Correct.**

#### Anonymous/Null Session (§2.2.4.53.1)
Per MS-SMB §2.2.4.53.1, a null session is indicated by `CaseInsensitivePasswordLength = 0`, `CaseSensitivePasswordLength = 0`, and empty `Account` string. KSMBD handles this by failing to find the user (`ksmbd_login_user("")` returns NULL) and returning `STATUS_LOGON_FAILURE`. **Issue:** Per MS-SMB and Windows behavior, a null session should be allowed if the server is configured to allow it (maps to guest account). KSMBD should check for a null session condition and route to a guest session rather than failing outright. **Fix:** Before calling `ksmbd_login_user()`, check if both password lengths are zero and the account name is empty; if so, and if the server is configured with `map to guest = Bad User` or equivalent, route to the guest/anonymous session path.

### 2.6 Multi-Session Handling (UID != 0 reuse path)

When a client sends `SMB_COM_SESSION_SETUP_ANDX` with a non-zero `Uid` (header field), KSMBD looks up the existing session and reuses it (lines 1403–1410). **Issue:** Per MS-SMB §2.2.4.53.1, when `Uid != 0` and the session exists, the packet is treated as a re-authentication or session update. The current code calls `ksmbd_user_session_get()` on the existing session but then proceeds into the normal authentication path which will attempt to `ksmbd_login_user()` again. If authentication fails, the existing session is destroyed. **Fix:** Separate the "new session" and "re-auth existing session" paths more clearly; on re-auth failure, preserve the original session rather than destroying it.

### 2.7 Security Implications

- The hard-coded "WORKGROUP" `PrimaryDomain` may mislead domain-joined clients.
- Anonymous session denial is spec non-compliant and may break compatibility with some legacy tools (net use, smbclient in anonymous mode).
- The `mechToken` length mismatch during NTLMSSP authentication decode (§2.3 issue 1) is a potential buffer over-read vulnerability and must be fixed.
- The VcNumber=0 reconnect logic absence means a client crash/reconnect may accumulate stale sessions, potentially exhausting session limits.

---

## 3. SMB_COM_TREE_CONNECT_ANDX (0x75)

### MS-SMB Reference
MS-SMB §2.2.4.55 — SMB_COM_TREE_CONNECT_ANDX Request/Response.

### 3.1 Request Parsing

#### Required Request Fields (§2.2.4.55.1, WordCount=4)
| Field | Handled | Notes |
|---|---|---|
| WordCount | Yes | Validated in `smb1misc.c` as 0x4 |
| AndXCommand | Yes | Chaining supported |
| Flags | **No** | See §3.1.1 |
| PasswordLength | Yes | Used to skip past password |
| ByteCount | Yes | |
| Password | Partial | Share-level password — see §3.1.2 |
| Path | Yes | UNC path to share |
| Service | Yes | Service type string |

##### 3.1.1 Flags Not Processed (§2.2.4.55.1)
The spec defines three flag bits:

| Flag | Value | Description |
|---|---|---|
| `TREE_CONNECT_ANDX_DISCONNECT_TID` | 0x0001 | Disconnect the TID in the request header before connecting |
| `TREE_CONNECT_ANDX_EXTENDED_SIGNATURES` | 0x0004 | Request extended security signatures on the connection |
| `TREE_CONNECT_ANDX_EXTENDED_RESPONSE` | 0x0008 | Client requests extended tree connect response (WordCount=7) |

**KSMBD status:** None of these flags are read or processed. The code unconditionally sends the extended response (WordCount=7) regardless of whether the client set `TREE_CONNECT_ANDX_EXTENDED_RESPONSE`. The `TREE_CONNECT_ANDX_DISCONNECT_TID` flag is never processed.

**Fixes required:**

1. **`TREE_CONNECT_ANDX_DISCONNECT_TID` (§2.2.4.55.1):** Per the spec, if this bit is set, the server MUST disconnect the TID specified in the request header before processing the tree connect. Implement as: read `req->Flags`, if `DISCONNECT_TID` bit set, call `smb_tree_disconnect()` for `req_hdr->Tid` before establishing the new tree connection.

2. **`TREE_CONNECT_ANDX_EXTENDED_RESPONSE` (§2.2.4.55.1):** The server SHOULD only send the extended (WordCount=7) response when this flag is set; otherwise it SHOULD send the basic (WordCount=3) response. Current behavior always sends WordCount=7. While most modern clients set this flag and will accept the extended response anyway, sending WordCount=7 when WordCount=3 was requested is a spec violation. **Fix:** Check the flag and send `smb_com_tconx_rsp` (WordCount=3) or `smb_com_tconx_rsp_ext` (WordCount=7) accordingly.

3. **`TREE_CONNECT_ANDX_EXTENDED_SIGNATURES` (§2.2.4.55.1):** If the client requests extended signatures and the server supports it, the server sets `SMB_EXTENDED_SIGNATURES` in the `OptionalSupport` field of the response. KSMBD does not implement extended (HMAC-MD5 per-packet) signatures at the SMB1 level. If the server cannot support extended signatures, the flag should be silently ignored and `SMB_EXTENDED_SIGNATURES` must not be set in `OptionalSupport`.

##### 3.1.2 Share-Level Password (§2.2.4.55.1)
Per MS-SMB §2.2.4.55.1, when the server is operating in share-level security mode (`SecurityMode` USER bit clear), clients provide a password in the `Password` field to access the share. KSMBD operates in user-level security mode (`SECMODE_USER` always set in negotiate response), so `Password` is expected to be empty (PasswordLength=0 or PasswordLength=1 with a null byte). The current code uses `PasswordLength` only as an offset to locate the `Path` field, which is correct. However, KSMBD does not validate that the Password is actually empty/null in user-level security mode, which could mask misuse or fuzzer inputs. **Low-priority fix:** Assert `PasswordLength == 0 || (PasswordLength == 1 && Password[0] == 0)` when in user-level mode.

### 3.2 Path and Service Type Parsing

The code parses the UNC path and service type (A:, LPT1:, IPC, COMM, ?????) from the ByteCount data area. The `dev_flags` mapping is:

```c
if (!strcmp(dev_type, "A:"))    dev_flags = 1;
else if (!strncmp(dev_type, "LPT", 3)) dev_flags = 2;
else if (!strcmp(dev_type, "IPC"))  dev_flags = 3;
else if (!strcmp(dev_type, "COMM")) dev_flags = 4;
else if (!strcmp(dev_type, "?????")) dev_flags = 5;
```

**Issue:** Per MS-SMB §2.2.4.55.1, the `Service` field can also be `"LPT1:"` (with colon and number). The current code checks `strncmp(dev_type, "LPT", 3)` which will match any LPT-prefixed string, including `"LPTX:"` strings with arbitrary device numbers. This is over-permissive but not a security issue. More critically, if a client sends `"LPT1:"` with the colon, it matches due to `strncmp`. The spec says printer shares use `"LPT1:"` as the service type — verify the comparison handles both `"LPT1:"` and `"LPT1"`.

**Issue:** Service type `"?????"` is treated as a wildcard that matches any share type. Per MS-SMB §2.2.4.55.1, `"?????"` means "any type" and the server should accept the connection regardless of the actual service type. KSMBD allows it through `dev_flags = 5`, but then the check `else if (!dev_flags || (dev_flags > 1 && dev_flags < 5))` at line 630 will reject it (`dev_flags=5` evaluates to false in the second condition, falling through). Actually tracing the logic:
- `dev_flags=5` is truthy (not zero), so the first `!dev_flags` is false.
- `(5 > 1 && 5 < 5)` is false.
- So `"?????"` on a disk share correctly passes. **No bug here.** But add a comment for clarity.

### 3.3 Response — Extended (WordCount=7)

#### Required Fields (§2.2.4.55.2, Extended Response)
| Field | KSMBD Status | Notes |
|---|---|---|
| WordCount=7 | Correct | `rsp->WordCount = 7` |
| AndXCommand | Correct | |
| OptionalSupport | Partial | See §3.3.1 |
| MaximalShareAccessRights | Partial | See §3.3.2 |
| GuestMaximalShareAccessRights | Partial | See §3.3.3 |
| ByteCount | Correct | |
| Service | Correct | ASCII, NUL-terminated |
| NativeFileSystem | Present | NTFS as UTF-16LE |

##### 3.3.1 OptionalSupport Bits (§2.2.4.55.2)
Current value:
```c
SMB_SUPPORT_SEARCH_BITS | SMB_CSC_NO_CACHING | SMB_UNIQUE_FILE_NAME
```

| Bit | Value | Set | Notes |
|---|---|---|---|
| `SMB_SUPPORT_SEARCH_BITS` | 0x0001 | Yes | Correct — exclusive searches supported |
| `SMB_SHARE_IS_IN_DFS` | 0x0002 | No | **Issue:** Should be set for DFS shares |
| `SMB_CSC_MASK` (0x000C) | varies | `SMB_CSC_NO_CACHING` (0x000C) | Correct for most shares; could be per-share config |
| `SMB_UNIQUE_FILE_NAME` | 0x0010 | Yes | Correct — 8.3 name uniqueness supported |
| `SMB_EXTENDED_SIGNATURES` | 0x0020 | No | Correct — not implemented |

**Fix needed:** Set `SMB_SHARE_IS_IN_DFS` when the share is a DFS share (check `test_share_config_flag(share, KSMBD_SHARE_FLAG_DFS)`). This is required for clients to initiate DFS referral logic.

##### 3.3.2 MaximalShareAccessRights (§2.2.4.55.2)
Current: `FILE_READ_RIGHTS | FILE_EXEC_RIGHTS` always, plus `FILE_WRITE_RIGHTS` if writable.

Per MS-SMB §2.2.4.55.2, this field is `MaximalShareAccessRights` — the maximum access rights the authenticated user has on this share. KSMBD uses a binary writable/non-writable distinction. This is a simplification; a more correct implementation would compute actual access rights based on the share's ACL and the user's credentials. **Low-priority enhancement, not a spec violation** for basic compliance.

**Issue:** `FILE_WRITE_RIGHTS` includes `DELETE` and related bits which may exceed the intended semantics for a writable share. Review the exact bit definitions used.

##### 3.3.3 GuestMaximalShareAccessRights (§2.2.4.55.2)
Current: hardcoded 0. This means guest users have no access to this share according to the response. If the share does allow guest access (e.g., `map to guest` configuration), this should reflect guest access rights. **Fix (low priority):** Set appropriately based on share guest policy.

### 3.4 Security Implications

- Not processing `TREE_CONNECT_ANDX_DISCONNECT_TID` is a protocol violation but has limited security impact; at worst a client cannot rely on the disconnect-then-connect atomicity guarantee.
- Always sending the extended response (WordCount=7) instead of the basic (WordCount=3) could confuse very old clients that did not set the extended flag, potentially causing length parse errors.

---

## 4. SMB_COM_LOGOFF_ANDX (0x74)

### MS-SMB Reference
MS-SMB §2.2.4.54 — SMB_COM_LOGOFF_ANDX Request/Response.

### 4.1 Request Parsing

#### Required Request Fields (§2.2.4.54.1, WordCount=2)
| Field | Handled | Notes |
|---|---|---|
| WordCount | Yes | Validated as 0x2 in `smb1misc.c` |
| AndXCommand | No | Chaining not processed |
| ByteCount | Yes | Validated as 0x0 |

Per MS-SMB §2.2.4.54.1, `ByteCount` must be 0. `smb1_get_byte_count()` enforces `bc == 0x0` for `SMB_COM_LOGOFF_ANDX`. **Correct.**

### 4.2 Session Teardown Logic

Handler: `smb_session_disconnect()` (line 440).

Current logic:
1. `ksmbd_conn_set_need_reconnect(conn)` — marks connection as needing reconnect.
2. `ksmbd_conn_wait_idle(conn)` — waits for in-flight requests to complete.
3. `ksmbd_tree_conn_session_logoff(sess)` — disconnects all tree connections for the session.
4. `ksmbd_conn_set_exiting(conn)` — tears down the entire connection.

**Issues:**

1. **Entire connection torn down instead of just the session (§2.2.4.54):** Per MS-SMB §2.2.4.54, `SMB_COM_LOGOFF_ANDX` invalidates only the `Uid` (session) associated with the request. Other sessions on the same connection must remain active (SMB1 supports multiple sessions per TCP connection via multiple UIDs). KSMBD calls `ksmbd_conn_set_exiting(conn)` which terminates the entire TCP connection, not just the session. This is a **significant spec violation**. If the connection has only one session, the behavior is acceptable. But if there are multiple sessions (multiple UIDs), this incorrectly tears them all down. **Fix required:** Only invalidate `work->sess` (the specific UID), call `ksmbd_session_destroy(sess)` for that session, and leave the connection and other sessions intact. Only transition `conn` to exiting if there are no remaining sessions.

2. **Response not explicitly built:** The `smb_session_disconnect()` handler returns 0, and the generic `init_smb_rsp_hdr()` has already zeroed the response buffer. The response header sets `WordCount=0` via the init path (line 224 of `smb1pdu.c`). However, per MS-SMB §2.2.4.54.2, the response requires `WordCount=2` (the AndX block) and `ByteCount=0`. The `init_smb_rsp_hdr()` initializes `WordCount=0`, but the LOGOFF_ANDX response must have `WordCount=2`. **Fix required:** Explicitly set `rsp->WordCount = 2`, `rsp->AndXCommand = SMB_NO_MORE_ANDX_COMMAND`, `rsp->AndXReserved = 0`, `rsp->AndXOffset = cpu_to_le16(get_rfc1002_len(rsp_hdr))`, `rsp->ByteCount = 0`, and call `inc_rfc1001_len(rsp_hdr, 2*2)`.

3. **AndX chaining not processed:** If the client sends an AndX command chained after `LOGOFF_ANDX`, the current handler ignores it. Per MS-SMB, if the logoff succeeds, subsequent AndX commands that do not require an authenticated session (like `SMB_COM_NEGOTIATE`) may be processed. In practice, chaining after a logoff is unusual, but the spec does not prohibit it.

4. **ksmbd_conn_wait_idle() before session destroy:** The current implementation waits for all connection-level requests to drain before logging off. This is overly conservative and introduces latency. The correct approach is to wait only for requests associated with `work->sess`, not all requests on the connection.

### 4.3 UID Invalidation (§2.2.4.54)

Per MS-SMB §2.2.4.54.1, after `SMB_COM_LOGOFF_ANDX` completes, the `Uid` specified in the request MUST be invalidated. Any subsequent requests with the same `Uid` MUST return `STATUS_SMB_BAD_UID`. KSMBD accomplishes this by removing the session from `conn->sessions` via `ksmbd_tree_conn_session_logoff()` and `ksmbd_session_destroy()`. **Correct in principle**, but the actual session lookup in `smb_check_user_session()` relies on `ksmbd_session_lookup()` which searches `conn->sessions`. If the session is properly removed, the invalidation is effective. **Verify** that `ksmbd_tree_conn_session_logoff()` + `ksmbd_session_destroy()` always removes the session from `conn->sessions`.

### 4.4 Security Implications

- Tearing down the entire TCP connection on logoff prevents a legitimate multi-session use case where a client holds multiple simultaneous sessions (e.g., one for a user account, one for an admin account on the same connection). This can cause client connection failures and force unnecessary reconnections.
- If the response `WordCount` is 0 instead of 2, a strict client will reject the response as malformed, causing it to potentially retry or hang.

---

## 5. SMB_COM_TREE_DISCONNECT (0x71)

### MS-SMB Reference
MS-SMB §2.2.4.51 — SMB_COM_TREE_DISCONNECT Request/Response.

### 5.1 Request Parsing

#### Required Request Fields (§2.2.4.51.1, WordCount=0)
| Field | Handled | Notes |
|---|---|---|
| WordCount | Yes | Validated as 0x0 in `smb1misc.c` |
| ByteCount | Yes | Validated as 0x0 in `smb1misc.c` |

**Correct.**

### 5.2 TID Invalidation and File Cleanup

Handler: `smb_tree_disconnect()` (line 463).

Current logic:
1. Validates `tcon != NULL`.
2. Calls `ksmbd_close_tree_conn_fds(work)` to close all open files.
3. Transitions `tcon->t_state = TREE_DISCONNECTED` under the write lock.
4. Calls `ksmbd_tree_conn_disconnect(sess, tcon)` to remove the tree connection.
5. Sets `work->tcon = NULL`.

**Issues:**

1. **Error code for invalid TID (§2.2.4.51):** When `tcon == NULL`, KSMBD returns `STATUS_NO_SUCH_USER`. Per MS-SMB §2.2.4.51, the correct error when the `Tid` is not valid is `STATUS_SMB_BAD_TID` (0xC000006F mapped to ERRSRV/ERRinvnid). **Fix:** Change the error code to `STATUS_SMB_BAD_TID` (or the CIFS error equivalent `ERRSRV/9`).

2. **Open file cleanup ordering (§2.2.4.51):** The spec states that the server SHOULD close all files opened through the tree connection. KSMBD calls `ksmbd_close_tree_conn_fds(work)` before marking the tree as disconnected, which is correct. However, the cleanup must handle in-flight operations (reads/writes) that may be accessing those file handles concurrently. **Verify** that `ksmbd_close_tree_conn_fds()` properly synchronizes against concurrent I/O workers. If not, file handle use-after-free is possible.

3. **Pending locks and oplocks (§2.2.4.51):** Per MS-SMB §2.2.4.51, all locks held through the disconnected tree must be released. KSMBD's `ksmbd_close_tree_conn_fds()` calls `ksmbd_close_fd()` which should release locks via the VFS. **Verify** that oplock releases are issued to other clients when a file is closed due to tree disconnect.

4. **Response fields:** Per MS-SMB §2.2.4.51.2, the response is `WordCount=0, ByteCount=0`. KSMBD does not explicitly set these in `smb_tree_disconnect()` — it relies on `init_smb_rsp_hdr()` having zero-initialized the buffer and set `WordCount=0`. The `ByteCount` is the 16-bit value immediately after the word parameters, which is also zeroed. **Correct by initialization, but fragile.** Explicitly setting `rsp_hdr->WordCount = 0; ((struct smb_hdr *)work->response_buf)->Status.CifsError = STATUS_SUCCESS;` would be more defensible.

5. **TREE_DISCONNECTED double-disconnect (§2.2.4.51):** If `tcon->t_state == TREE_DISCONNECTED` already, KSMBD returns `STATUS_NETWORK_NAME_DELETED`. Per MS-SMB §2.2.4.51, the behavior for disconnecting an already-disconnected TID is not explicitly specified; returning an error is acceptable. **Low priority.**

### 5.3 Security Implications

- Using `STATUS_NO_SUCH_USER` instead of `STATUS_SMB_BAD_TID` for an invalid TID may confuse clients and diagnostics.
- If concurrent I/O is not properly quiesced before closing tree connection file handles, memory safety issues can occur.

---

## 6. Summary of Required Fixes by Priority

### Priority 1 — Correctness / Spec Violations

| ID | Command | Issue | File / Line |
|---|---|---|---|
| N-01 | NEGOTIATE | `MaxRawSize` must be 0 when `CAP_RAW_MODE` not set | `smb1pdu.c:1011` |
| N-02 | NEGOTIATE | Missing `DomainName` field in non-extended-security response | `smb1pdu.c:1027–1035` |
| N-03 | NEGOTIATE | Wrong error code (`STATUS_INVALID_LOGON_TYPE`) for no-common-dialect; should be `DialectIndex=0xFFFF, STATUS_SUCCESS` | `smb1pdu.c:988–991` |
| N-04 | NEGOTIATE | `CAP_MPX_MODE` missing despite `MaxMpxCount=10` | `smb1pdu.h:31–35` |
| S-01 | SESSION_SETUP | Missing `NativeOS`, `NativeLanMan`, `PrimaryDomain` in extended security response | `smb1pdu.c:build_sess_rsp_extsec` |
| S-02 | SESSION_SETUP | `PrimaryDomain` hardcoded to "WORKGROUP" instead of `server_conf.work_group` | `smb1pdu.c:1164` |
| S-03 | SESSION_SETUP | `mechToken` length vs `SecurityBlobLength` mismatch in NTLMSSP auth decode (potential over-read) | `smb1pdu.c:1326` |
| S-04 | SESSION_SETUP | `VcNumber=0` must disconnect existing sessions before creating new one | `smb1pdu.c:smb_session_setup_andx` |
| S-05 | SESSION_SETUP | Invalid `WordCount` should respond with error, not silently drop | `smb1pdu.c:1396–1398` |
| T-01 | TREE_CONNECT | `TREE_CONNECT_ANDX_DISCONNECT_TID` flag not processed | `smb1pdu.c:smb_tree_connect_andx` |
| T-02 | TREE_CONNECT | Extended response (WC=7) always sent; should be conditional on `TREE_CONNECT_ANDX_EXTENDED_RESPONSE` flag | `smb1pdu.c:643` |
| L-01 | LOGOFF_ANDX | Entire TCP connection torn down instead of only the specific UID's session | `smb1pdu.c:446–453` |
| L-02 | LOGOFF_ANDX | Response `WordCount` must be 2, not 0 | `smb1pdu.c:smb_session_disconnect` |
| D-01 | TREE_DISCONNECT | Error for invalid TID should be `STATUS_SMB_BAD_TID`, not `STATUS_NO_SUCH_USER` | `smb1pdu.c:473` |

### Priority 2 — Compliance Enhancement

| ID | Command | Issue |
|---|---|---|
| N-05 | NEGOTIATE | Add `CAP_RPC_REMOTE_APIS` for IPC$/named-pipe support |
| N-06 | NEGOTIATE | Add `CAP_INFOLEVEL_PASSTHRU` for TRANS2 passthrough levels |
| N-07 | NEGOTIATE | Add `CAP_DFS` when DFS is configured |
| S-06 | SESSION_SETUP | Handle null/anonymous session (empty account, zero passwords) gracefully |
| S-07 | SESSION_SETUP | Fix Unicode alignment padding in no-extsc variant (hard-coded `+1`) |
| S-08 | SESSION_SETUP | Multi-session: on re-auth failure preserve existing session |
| T-03 | TREE_CONNECT | Set `SMB_SHARE_IS_IN_DFS` in `OptionalSupport` for DFS shares |
| T-04 | TREE_CONNECT | Validate that `Password` is null in user-level security mode |

### Priority 3 — Low-Priority / Documentation

| ID | Command | Issue |
|---|---|---|
| N-08 | NEGOTIATE | `ServerTimeZone` always 0; consider exposing config option |
| N-09 | NEGOTIATE | Pre-NT dialect response format (PC NETWORK PROGRAM 1.0 etc.) if ever needed |
| T-05 | TREE_CONNECT | `GuestMaximalShareAccessRights` always 0; populate from share guest policy |
| D-02 | TREE_DISCONNECT | Verify oplock release for files closed via tree disconnect |

---

## 7. Cross-Cutting Concerns

### 7.1 AndX Chaining
All five commands participate in AndX chaining. The current implementation processes the initial command and chains to the next only when the handler returns a non-negative `AndXCommand` value. The chaining path in `smb1pdu.c` correctly loops through AndX commands. **Verify** that the chaining logic does not allow unbounded recursion (the loop depth is bounded by the packet size, but ensure there is an explicit maximum depth check to prevent a crafted packet from consuming excessive CPU via deeply nested AndX chains).

### 7.2 Flags2 Consistency
The negotiate response sets `Flags2 = rcv_hdr->Flags2` (line 220 in `init_smb_rsp_hdr()`). This echoes back the client's `Flags2` which may include bits the server does not support. A stricter implementation should mask the response `Flags2` to only bits the server has advertised. In particular:
- `SMBFLG2_DFS` should only be set if DFS is configured.
- `SMBFLG2_EXT_SEC` should only be set if extended security was negotiated.

### 7.3 Signing Verification Bypass
`smb1misc.c` correctly skips signature verification for `SMB_COM_NEGOTIATE` (no session key) and the first `SMB_COM_SESSION_SETUP_ANDX` when no session exists. This is per spec. All subsequent commands, including `SMB_COM_TREE_CONNECT_ANDX`, `SMB_COM_LOGOFF_ANDX`, and `SMB_COM_TREE_DISCONNECT`, must have their signatures verified if signing was negotiated. The existing signing gate in `smb1pdu.c` lines 8964–8968 implements this correctly.
