# SMB3 Plan 03: Message Signing

Audit date: 2026-03-01
Branch: phase1-security-hardening
Spec reference: MS-SMB2 §3.3.5.2.4, §3.3.5.5.3, §3.3.5.2.7, §3.3.5.2.7.3

---

## Signing Algorithm Selection

### Algorithm constants and negotiation (MS-SMB2 §3.3.5.2.4)

`SIGNING_ALG_HMAC_SHA256 = 0x0000`, `SIGNING_ALG_AES_CMAC = 0x0001`, `SIGNING_ALG_AES_GMAC = 0x0002` are correctly defined at `src/include/protocol/smb2pdu.h:366-368`.

**Per-dialect default assignment** in `src/protocol/smb2/smb2ops.c`:

| Dialect | Function | conn->signing_algorithm set | Correct per spec? |
|---------|----------|----------------------------|-------------------|
| SMB 2.0 | `init_smb2_0_server()` L237 | `SIGNING_ALG_HMAC_SHA256` | Yes |
| SMB 2.1 | `init_smb2_1_server()` L256 | `SIGNING_ALG_HMAC_SHA256` | Yes |
| SMB 3.0 | `init_smb3_0_server()` L282 | `SIGNING_ALG_AES_CMAC` | Yes |
| SMB 3.0.2 | `init_smb3_02_server()` L317 | `SIGNING_ALG_AES_CMAC` | Yes |
| SMB 3.1.1 | `init_smb3_11_server()` L355 | `SIGNING_ALG_AES_CMAC` (default) | Partial — overwritten by negotiate context if client sends one |

**SMB 3.1.1 negotiate context** (`decode_sign_cap_ctxt()` at `src/protocol/smb2/smb2_negotiate.c:421-483`):

- Validates `SigningAlgorithmCount > 0` (L439).
- Iterates client proposals, assigns priorities: HMAC-SHA256=0, AES-CMAC=1, AES-GMAC=2. Picks highest (L457-481).
- If no common algorithm: falls back to `SIGNING_ALG_AES_CMAC` (L481).
- Sets `conn->signing_negotiated = true` (L473).
- Final value echoed back in `assemble_neg_contexts()` (L232-246) when `conn->signing_negotiated`.

**Bug:** SMB 3.1.1 initial default at L355 is `SIGNING_ALG_AES_CMAC`. If the client sends NO `SMB2_SIGNING_CAPABILITIES` context (allowed by spec), the default `AES_CMAC` remains in `conn->signing_algorithm`, which is correct. However, if the client does send a context but only offers `HMAC_SHA256`, the code accepts it (priority 0) and uses HMAC-SHA256 with SMB 3.1.1 keys derived with the "SMBSigningKey" label. This is spec-compliant (the spec allows any negotiated algorithm for 3.1.1), but the combination is unusual.

**Conformance:** Algorithm selection is correct.

---

## Signing Key Derivation

### SMB 2.0 / 2.1 — HMAC-SHA256 with session key directly

Per MS-SMB2 §3.3.5.5.3: the signing key for dialects 2.0/2.1 is the first 16 bytes of the `SessionKey`.

In `smb2_check_sign_req()` (`src/protocol/smb2/smb2_pdu_common.c:973`) and `smb2_set_sign_rsp()` (L1019):

```c
ksmbd_sign_smb2_pdu(work->conn, work->sess->sess_key, iov, 1, signature)
```

`ksmbd_sign_smb2_pdu()` (`src/core/auth.c:996-1036`) uses:

```c
crypto_shash_setkey(CRYPTO_HMACSHA256_TFM(ctx), key, SMB2_NTLMV2_SESSKEY_SIZE);
```

`SMB2_NTLMV2_SESSKEY_SIZE = 16` (`src/include/protocol/smb2pdu.h:81`). So the first 16 bytes of `sess->sess_key` are used as the HMAC key. This is correct.

**Issue:** `sess->sess_key` is 16 bytes wide (set by `ksmbd_gen_sess_key()` at `src/core/auth.c:232`). The full `sess_key` is used, not a truncated copy. This is correct per the spec.

### SMB 3.0 / 3.0.2 — SP800-108 KDF with "SMB2AESCMAC\0" label

`ksmbd_gen_smb30_signingkey()` (`src/core/auth.c:1336-1348`):

```c
d.label.iov_base = "SMB2AESCMAC";
d.label.iov_len = 12;          // includes NUL terminator in string literal
d.context.iov_base = "SmbSign";
d.context.iov_len = 8;         // includes NUL terminator in string literal
```

**Bug P1 — Label length for SMB 3.0 signing key:**

The MS-SMB2 specification (§3.1.4.2) mandates the label `"SMB2AESCMAC\0"` which is 12 bytes (11 chars + 1 NUL). In the code, `d.label.iov_len = 12` and `d.label.iov_base = "SMB2AESCMAC"`. The C string literal `"SMB2AESCMAC"` is 12 bytes including the implicit NUL terminator (`\0`), so iov_len = 12 correctly captures `SMB2AESCMAC\0`. This is correct.

**Bug P1 — Context for SMB 3.0 signing key:**

The spec mandates context = `"SmbSign\0"` (8 bytes). `d.context.iov_len = 8` and `d.context.iov_base = "SmbSign"` is 8 bytes including NUL. This is correct.

`generate_key()` at `src/core/auth.c:1219` implements the SP800-108 PRF as:

```
HMAC-SHA256(SessionKey, i=1 || label || 0x00 || context || L)
```

Where `L = 128` (for 16-byte key). This follows MS-SMB2 §3.1.4.2. Correct.

### SMB 3.1.1 — SP800-108 KDF with "SMBSigningKey\0" + preauth hash

`ksmbd_gen_smb311_signingkey()` (`src/core/auth.c:1350-1378`):

```c
d.label.iov_base = "SMBSigningKey";
d.label.iov_len = 14;          // "SMBSigningKey\0" = 14 bytes
d.context.iov_base = sess->Preauth_HashValue;  // 64-byte SHA-512 preauth hash
d.context.iov_len = 64;
```

The spec (§3.3.5.5.3) mandates label `"SMBSigningKey\0"` (14 bytes) and context = preauthSessionHashValue (64 bytes). Both match. Correct.

**For session binding (multichannel):** The preauth hash comes from `preauth_sess->Preauth_HashValue` (from the binding session-setup exchange), not the original session. This is correct per §3.3.5.5.3.

**Key storage:**

- `sess->smb3signingkey` stores the session-level signing key (used for SESSION_SETUP responses and when no channel exists).
- `chann->smb3signingkey` stores the channel-level signing key.
- `generate_smb3signingkey()` at L1307: for non-binding, key is generated into `sess->smb3signingkey` then copied to `chann->smb3signingkey` (L1330). For binding, key goes into `chann->smb3signingkey` directly (L1320). This is correct per the spec.

---

## Signing Implementation

### HMAC-SHA256 (`ksmbd_sign_smb2_pdu`, auth.c:996)

- Uses `crypto_shash` HMAC-SHA256 from kernel crypto API.
- Key: first 16 bytes of session key (`SMB2_NTLMV2_SESSKEY_SIZE`).
- Hash is computed over all iovecs (full SMB2 message starting from `hdr->ProtocolId`).
- Output is 32 bytes; only first 16 bytes (`SMB2_SIGNATURE_SIZE`) are copied into the Signature field.
- **Signature field zeroing before signing:** Done at `smb2_check_sign_req()` L997: `memset(hdr->Signature, 0, SMB2_SIGNATURE_SIZE)` before calling `ksmbd_sign_smb2_pdu`. Done at `smb2_set_sign_rsp()` L1028 similarly.
- **NetBIOS length field excluded:** The iov base is `(char *)&hdr->ProtocolId` (L999, L1105), which is 4 bytes past the start of the buffer (past the RFC1001 4-byte length field). This is correct — the NetBIOS framing layer is NOT included in the SMB2 signature computation.

### AES-CMAC (`ksmbd_sign_smb3_pdu`, auth.c:1047)

- Uses `crypto_shash` CMAC(AES) primitive from kernel.
- Key: 16-byte derived signing key.
- Hash over all iovecs. Correct.
- Signature zeroed before call (L1104 in `smb3_check_sign_req`, L1160 in `smb3_set_sign_rsp`).

### AES-GMAC (`ksmbd_sign_smb3_pdu_gmac`, auth.c:1102)

AES-GMAC is GCM with zero-length plaintext. The SMB2 message acts as AAD and the 16-byte GCM auth tag is the signature.

**Nonce construction (auth.c:1120-1122):**

```c
hdr = (struct smb2_hdr *)iov[0].iov_base;
memcpy(nonce, &hdr->MessageId, sizeof(hdr->MessageId));
/* Remaining 4 bytes of nonce are already zeroed */
```

The nonce is 12 bytes: 8 bytes = MessageId (LE), then 4 bytes zero. Per MS-SMB2 §3.1.4.1.1, the 12-byte nonce for AES-GMAC signing is constructed as: `Nonce = MessageId || 0x00000000`. This matches exactly. Correct.

**AEAD setup (auth.c:1186-1194):**

```c
aead_request_set_crypt(req, sg, sg, 0, nonce);   // 0 plaintext bytes
aead_request_set_ad(req, total_len);              // entire message as AAD
```

With `plaintext_len = 0`, this is pure GMAC. The authentication tag (`tag[16]`) becomes the signature. Correct.

**Key size for GMAC (L1132):** Uses `SMB2_CMACAES_SIZE = 16`. AES-GMAC for SMB signing uses a 128-bit key (same size as AES-CMAC key). Correct.

**Issue — linearization overhead:** The implementation linearizes all iovecs into `aad_buf` with `kzalloc(total_len)` (L1159). For large READ responses, this means a potentially large allocation and copy. This is a performance concern but not a correctness bug.

**Signature field zeroing:** In `smb3_check_sign_req()` L1104, the Signature field is zeroed before the data is passed to the signing function. In `smb3_set_sign_rsp()` L1160, the same. The message is linearized into `aad_buf` after zeroing, so the signing input has a zero Signature field. Correct.

### Compound request iov selection

**READ response special case** (`smb2_set_sign_rsp` L1030-1041, `smb3_set_sign_rsp` L1162-1173):

For `SMB2_READ`, `n_vec = 2` and `iov = &work->iov[work->iov_idx - 1]`. This includes the response header AND the read payload. This is correct — the entire response including payload must be signed.

For all other commands, `iov = &work->iov[work->iov_idx]`, `n_vec = 1`. Correct.

---

## Enforcement and Compound Signing

### Signing enforcement in request dispatch (`src/core/server.c:192-197`)

```c
if (work->sess && conn->ops->is_sign_req(work, command)) {
    ret = conn->ops->check_sign_req(work);
    if (!ret) {
        conn->ops->set_rsp_status(work, STATUS_ACCESS_DENIED);
        return SERVER_HANDLER_CONTINUE;
    }
}
```

- Signing check is performed **before** command dispatch. Correct.
- Returns `STATUS_ACCESS_DENIED` for failed signature verification. Per MS-SMB2 §3.3.5.2.4, the server MUST return `STATUS_ACCESS_DENIED`. Correct.
- The check is gated on `work->sess != NULL`. If there is no session (e.g. the command doesn't require one), signing is skipped. For commands that bypass session lookup (NEGOTIATE, SESSION_SETUP, ECHO), `work->sess` will be NULL here.

### `smb2_is_sign_req()` analysis (`smb2_pdu_common.c:925-965`)

| Condition | Return | Spec conformance |
|-----------|--------|-----------------|
| `SMB2_NEGOTIATE_HE` | false | Correct — NEGOTIATE is never signed (§3.3.5.2.4) |
| `SMB2_OPLOCK_BREAK_HE` | false | Partial — spec says OPLOCK_BREAK responses from server don't carry client signatures, but client acknowledgments SHOULD be signed if session signing is active. Skipping all OPLOCK_BREAK signing may miss cases where the client acknowledgment carries SMB2_FLAGS_SIGNED. |
| Related compound sub-request | false | Correct — §3.3.5.2.3: related sub-requests inherit context, not individually verified |
| `SMB2_SESSION_SETUP_HE` without `SMB2_FLAGS_SIGNED` | false | Correct — initial auth rounds have no key yet |
| `SMB2_FLAGS_SIGNED` set in header | true | Correct |
| `sess->sign == true` | true | Correct — server-mandated signing |

**Issue P2 — Unsigned requests when sess->sign=true are not rejected:**

`smb2_is_sign_req()` returns `true` if `sess->sign` is set, even when `SMB2_FLAGS_SIGNED` is NOT set in the request header. The subsequent `check_sign_req()` will compute a HMAC over the message with a zero Signature field, which will not match the real signed value — so it will return 0 and the request will be rejected with `STATUS_ACCESS_DENIED`. This is correct behavior for the mandatory-signing case. However, the mechanism is indirect: it relies on the signature mismatch rather than an explicit flag check. This works correctly.

**Issue P2 — CANCEL command:**

`SMB2_CANCEL_HE` is not excluded from signing checks. The spec (§3.3.5.16) states that CANCEL is not signed. If `sess->sign` is true and the client sends CANCEL without `SMB2_FLAGS_SIGNED`, the server will attempt to verify a zero signature and fail, returning `STATUS_ACCESS_DENIED`. This would prevent legitimate CANCEL requests on a signing-required session.

```
src/protocol/smb2/smb2_pdu_common.c:929-931
// CANCEL is not explicitly excluded:
if (command == SMB2_NEGOTIATE_HE ||
    command == SMB2_OPLOCK_BREAK_HE)
    return false;
```

### Response signing (`server.c:371-374`)

```c
if (work->sess &&
    (work->sess->sign || smb3_11_final_sess_setup_resp(work) ||
     conn->ops->is_sign_req(work, command)))
    conn->ops->set_sign_rsp(work);
```

- `sess->sign`: signs all responses when mandatory signing is active.
- `smb3_11_final_sess_setup_resp()`: signs the final (success) SESSION_SETUP response for SMB 3.0+ sessions. Per §3.3.5.5.3, the server MUST sign the successful SESSION_SETUP response with the newly derived signing key. This is correctly detected at `smb2_pdu_common.c:1389-1406`.
- `is_sign_req()`: mirrors request-side logic for response.

**Compound response signing:**

The `do { ... } while (is_chained)` loop in `server.c:253-375` calls `set_sign_rsp()` for each compound element individually. The `ksmbd_resp_buf_curr()` macro returns the current response header in the chain. Each compound response element is signed independently with the current element's data. This follows the spec requirement that each response in a compound is signed individually.

### Compound REQUEST signing (MS-SMB2 §3.3.5.2.7.3)

For an **unrelated compound request**: each command has its own signature, independently verified. In `smb2_is_sign_req()`, unrelated compound commands go through the normal path (not skipped by the `SMB2_FLAGS_RELATED_OPERATIONS` check), so each is verified independently. Correct.

For a **related compound request**: sub-requests after the first inherit the signing context. The server does NOT individually verify related sub-request signatures. In `smb2_is_sign_req()` L946-947: `if (rcv_hdr->Flags & SMB2_FLAGS_RELATED_OPERATIONS) return false`. Correct per spec.

**Issue P1 — Related compound: signing of first request verified, but subsequent related sub-requests not verified:**

This is actually correct by spec: only the first request in a related compound chain needs to be signed. The remaining requests inherit the session context. However, this means a MITM could tamper with related sub-requests after the first, and the server would process them as if they came from the authenticated client. This is a known spec limitation, not an implementation bug.

---

## Multichannel Signing

### Session binding (MS-SMB2 §3.3.5.5.3 / §3.3.5.2.7)

The session binding path is in `smb2_sess_setup()` (`src/protocol/smb2/smb2_session.c`):

1. **Binding flag check (L594-597):** If `SMB2_SESSION_REQ_FLAG_BINDING` is set, verifies `SMB2_FLAGS_SIGNED` is present in the request header. If not, rejects with `-EINVAL`. Correct — per §3.3.5.2.7, binding requests MUST be signed.

2. **Signature verification (L678-685):** After `work->sess` is set, calls `conn->ops->check_sign_req(work)`. This verifies the binding SESSION_SETUP request against the existing session's signing key. Correct.

3. **Key selection in `smb3_check_sign_req()` (smb2_pdu_common.c:1088-1096):** For `SMB2_SESSION_SETUP_HE`, uses `work->sess->smb3signingkey` (the session-level key, not the channel key). For all other commands, uses `chann->smb3signingkey`. This is correct: during binding, the existing session's signing key is used to authenticate the binding request.

4. **New channel key derivation (auth.c:1307-1333):** For binding (`conn->binding == true`), `generate_smb3signingkey()` stores the new key in `chann->smb3signingkey`. For the non-binding initial session, it stores in both `sess->smb3signingkey` and `chann->smb3signingkey`. This is correct.

5. **Multichannel: conn->binding reset** (`smb2_session.c:571, 636, 666`): `conn->binding` is set to `false` for non-binding setup and `true` for binding. The response signing in `smb3_set_sign_rsp()` at L1143-1151 uses `work->sess->smb3signingkey` when `conn->binding == false` AND command is `SESSION_SETUP`, otherwise uses `chann->smb3signingkey`. This is correct.

---

## Confirmed Bugs (P1)

### P1-01: SMB2_CANCEL not excluded from signing enforcement
**File/Line:** `src/protocol/smb2/smb2_pdu_common.c:929-931`
**Symptom:** When `sess->sign = true` (mandatory signing), CANCEL requests without `SMB2_FLAGS_SIGNED` will be rejected with `STATUS_ACCESS_DENIED` instead of being processed. This prevents the client from cancelling in-flight async requests on a signing-required session.
**Spec ref:** MS-SMB2 §3.3.5.16: "The server MUST NOT require the SMB2 CANCEL Request to be signed."
**Fix:** Add `SMB2_CANCEL_HE` to the exclusion list in `smb2_is_sign_req()`, alongside `SMB2_NEGOTIATE_HE`.

```c
// Before:
if (command == SMB2_NEGOTIATE_HE ||
    command == SMB2_OPLOCK_BREAK_HE)
    return false;

// After:
if (command == SMB2_NEGOTIATE_HE ||
    command == SMB2_OPLOCK_BREAK_HE ||
    command == SMB2_CANCEL_HE)
    return false;
```

### P1-02: SMB 3.0 signing key derivation label mismatch
**File/Line:** `src/core/auth.c:1341-1344`

Re-examination: `"SMB2AESCMAC"` has 11 characters; with NUL that is 12 bytes. `iov_len = 12` captures all 12 bytes including NUL. Similarly, `"SmbSign"` has 7 characters plus NUL = 8 bytes; `iov_len = 8`. Both match the spec. **This is NOT a bug.** (Retracted from P1.)

### P1-03: AES-GMAC nonce reuse risk across sessions
**File/Line:** `src/core/auth.c:1120-1122`
**Symptom:** The AES-GMAC nonce is derived from `MessageId` only. If two sessions (or a session reconnect) happen to use the same MessageId with the same signing key, the nonce is reused. AES-GCM with nonce reuse completely breaks confidentiality (and in this case, signature forgery becomes possible).
**Spec ref:** MS-SMB2 §3.1.4.1.1 specifies the nonce = MessageId || 0x00000000. The spec design relies on MessageId being unique per connection. However, after reconnect or on multiple channels, MessageIds restart. If the signing key is also reused, nonce+key collision is possible.
**Analysis:** In practice, `generate_smb3signingkey()` is called per session/channel setup, so the key changes per session. MessageId reuse across sessions with the same key would require a key reuse scenario (e.g., session binding not regenerating the channel key). Review: on session binding, `chann->smb3signingkey` is regenerated (L1320). So this risk exists only in a reconnect-without-new-key scenario. The current code always regenerates keys on new session setup, making this a theoretical concern rather than an exploitable current bug. **Downgrade to P3.**

### P1-04: `smb2_check_sign_req` returns 0 when `work->sess == NULL` — signing bypass
**File/Line:** `src/protocol/smb2/smb2_pdu_common.c:981-983`
```c
if (!work->sess)
    return 0;   // returns FAILURE, not success
```
**Symptom:** When `check_sign_req()` returns 0, `server.c:194` treats this as signing failure and returns `STATUS_ACCESS_DENIED`. This is the correct interpretation (0 = verification failed). However, `smb2_is_sign_req()` at L961 checks `work->sess && work->sess->sign`, so if `work->sess == NULL`, `is_sign_req()` would return false based on `SMB2_FLAGS_SIGNED` alone. The guard at `server.c:192` is `if (work->sess && ...)`, so if `work->sess == NULL`, `is_sign_req()` is never called. There is no bypass. **Not a bug.**

### P1-05: SMB2_OPLOCK_BREAK client acknowledgment signing skipped
**File/Line:** `src/protocol/smb2/smb2_pdu_common.c:930`
**Symptom:** All OPLOCK_BREAK commands (both server-to-client notifications and client acknowledgments) are excluded from signing. Client OPLOCK_BREAK acknowledgments sent by the client on a signing-required session should carry `SMB2_FLAGS_SIGNED` and be verified. By always returning `false` for `SMB2_OPLOCK_BREAK_HE`, a client could send an unsigned oplock break acknowledgment on a signing-required session.
**Spec ref:** MS-SMB2 §3.3.5.19: The client MUST sign the OPLOCK_BREAK acknowledgment if the session has signing enabled. The server SHOULD verify it.
**Fix:** Remove `SMB2_OPLOCK_BREAK_HE` from the unconditional exclusion, and instead only skip verification when `!(rcv_hdr->Flags & SMB2_FLAGS_SIGNED)` and `!sess->sign`.

---

## Missing Features (P2)

### P2-01: No enforcement that unsigned commands are rejected on mandatory-signing sessions beyond signature mismatch
**File/Line:** `src/core/server.c:192-197`
**Description:** The current enforcement relies on `check_sign_req()` computing a signature over a zeroed Signature field and comparing it to the client's zero Signature field (or the absent signature). The actual check correctly rejects unsigned requests via signature mismatch. However, per §3.3.5.2.4, the server SHOULD also check `SMB2_FLAGS_SIGNED` explicitly before attempting crypto. An explicit flag check before the crypto check would be cleaner and would save unnecessary crypto operations on unsigned requests.

### P2-02: No rate-limiting or logging of repeated signing failures
**File/Line:** `src/protocol/smb2/smb2_pdu_common.c:1006-1009` (smb2_check_sign_req)
**Description:** `pr_err_ratelimited("bad smb2 signature\n")` logs but does not disconnect or track repeated failures. An attacker performing signature forgery attempts would only be rate-limited in log output, not in connection behavior. Consider tracking per-connection signature failure counts and disconnecting after N failures.

### P2-03: Session binding signature verification error response
**File/Line:** `src/protocol/smb2/smb2_session.c:681-684`
```c
rc = -EACCES;
goto out_err;
```
`-EACCES` maps to `STATUS_REQUEST_NOT_ACCEPTED` (L779). Per MS-SMB2 §3.3.5.5.3, binding request signature verification failure should result in `STATUS_ACCESS_DENIED`, not `STATUS_REQUEST_NOT_ACCEPTED`.

### P2-04: SMB 3.1.1 with AES-GMAC: no key rotation mechanism
**File/Line:** N/A
**Description:** Per AES-GCM security requirements, a given key should not be used beyond 2^32 invocations (NIST SP 800-38D). The code has GCM nonce counter exhaustion handling for encryption (`src/protocol/smb2/smb2_pdu_common.c:1246`) but no equivalent for AES-GMAC signing. A long-lived session with high request rates could exhaust the nonce space. Note: with MessageId-based nonces, the practical limit is 2^64 messages per session, which is not exhaustible in practice.

### P2-05: Signing not applied to SMB2_CHANGE_NOTIFY async completion on all paths
**File/Line:** `src/fs/ksmbd_notify.c:226-229`, `src/fs/ksmbd_notify.c:389-392`
**Description:** CHANGE_NOTIFY async completions do check `is_sign_req` and call `set_sign_rsp`. However, the async path bypasses the main `__handle_ksmbd_work` sign logic (which runs `set_sign_rsp` in the main loop). The async completion code duplicates the sign logic. If a new notification path is added without copying this pattern, signing would be missed.

---

## Partial (P3)

### P3-01: AES-GMAC nonce collision theoretical risk across reconnects
**File/Line:** `src/core/auth.c:1120-1122`
**Description:** MessageId-based nonce is per-spec. After session reconnect, if the signing key were somehow reused (it is not in current code), MessageId collision would create nonce reuse. Current code regenerates keys on each session setup, making this theoretical. Monitoring recommended.

### P3-02: SMB 2.0/2.1 signature computed over entire message payload
**File/Line:** `src/protocol/smb2/smb2_pdu_common.c:988-994`
**Description:** For compound requests, `smb2_check_sign_req()` computes the signature over `NextCommand` bytes for non-terminal commands, and over the remainder for the last command. This is correct per §3.3.5.2.4. However, the iov-based calculation only has a single iov entry (`iov[0]`). This means READ responses with separate payload iovecs would miss the payload in the request check path. For request checking, a READ request has no separate payload iov, so this is fine. For response signing (`smb2_set_sign_rsp`), the READ special case adds `n_vec = 2`. Consistent. Correct.

### P3-03: KDF counter `i` hardcoded to `{0,0,0,1}`
**File/Line:** `src/core/auth.c:1224`
**Description:** The SP800-108 counter `i` is always `{0,0,0,1}` (value = 1). Per the KDF spec, for generating a single key this is correct (only one iteration needed). If ever extended to generate longer keys (>32 bytes) with multiple iterations, this would need to increment. Currently correct.

### P3-04: AES-GMAC uses linearized buffer copy
**File/Line:** `src/core/auth.c:1159-1173`
**Description:** All iovecs are copied into a contiguous `aad_buf` for the GMAC computation. For large compound requests or READ signing, this requires a full memory copy. A scatter-gather approach using `aead_request_set_ad` with separate SG entries for each iov would be more efficient but is not implemented.

---

## Low Priority (P4)

### P4-01: Stale comment in `ksmbd_sign_smb2_pdu` log message
**File/Line:** `src/core/auth.c:1004`
```c
ksmbd_debug(AUTH, "could not crypto alloc hmacmd5\n");
```
The function uses HMAC-SHA256, not HMAC-MD5. The log message is misleading.

### P4-02: `smb2_check_sign_req` ignores compound last-message length calculation for non-SMB3 path
**File/Line:** `src/protocol/smb2/smb2_pdu_common.c:988-994`
**Description:** For `smb2_check_sign_req` (SMB 2.x), the length calculation for the last command in a compound (`get_rfc1002_len - next_smb2_rcv_hdr_off`) includes the RFC1002 4-byte length field in `get_rfc1002_len`. The iov base starts at `hdr->ProtocolId` which is 4 bytes past the wire buffer start. The length arithmetic is therefore:

```
len = get_rfc1002_len(buf) - offset
```

`get_rfc1002_len` returns the payload length (not including the 4-byte RFC1001 header). `next_smb2_rcv_hdr_off` is the offset from the start of the SMB2 payload (after RFC1001 header). This arithmetic is consistent. Correct.

### P4-03: No check for `SIGNING_REQUIRED` in server's SecurityMode response vs actual signing enforcement
**File/Line:** `src/protocol/smb2/smb2_negotiate.c:906-907`
**Description:** When `server_conf.signing == KSMBD_CONFIG_OPT_MANDATORY`, the server sets `SMB2_NEGOTIATE_SIGNING_REQUIRED_LE` in the response and sets `conn->sign = true`. The client is supposed to honor this by setting `SMB2_FLAGS_SIGNED` on all subsequent signed requests. The server correctly enforces via `sess->sign`. However, there is no check that the client actually set `SMB2_NEGOTIATE_SIGNING_REQUIRED` in its own request SecurityMode when the server requires it. A client that sets `SIGNING_ENABLED` but not `SIGNING_REQUIRED` in its negotiate request, while the server requires signing, should be handled. The server correctly requires signing regardless of the client's SecurityMode in this case.

---

## Compliance Estimate

| Area | Status | Score |
|------|--------|-------|
| Algorithm selection (HMAC-SHA256, AES-CMAC, AES-GMAC) | Correct per dialect | 95% |
| SMB 3.1.1 signing capabilities negotiate context | Correct, priority selection works | 95% |
| SMB 2.x key derivation (first 16 bytes of SessionKey) | Correct | 100% |
| SMB 3.0/3.0.2 KDF ("SMB2AESCMAC\0") | Correct | 100% |
| SMB 3.1.1 KDF ("SMBSigningKey\0" + preauth hash) | Correct | 100% |
| Signature field zeroed before signing | Correct | 100% |
| NetBIOS/RFC1001 length excluded from SMB2 signature | Correct | 100% |
| HMAC-SHA256 implementation | Correct | 100% |
| AES-CMAC implementation | Correct | 100% |
| AES-GMAC implementation | Correct (spec-compliant nonce, zero-plaintext GMAC) | 95% |
| Signing enforcement before dispatch | Correct | 100% |
| STATUS_ACCESS_DENIED on signing failure | Correct | 100% |
| Compound request: independent unrelated, inherited related | Correct | 100% |
| Compound response: each element signed independently | Correct | 95% |
| Session binding: must be signed, verified with existing key | Correct | 90% |
| Multichannel: channel-level signing key | Correct | 95% |
| SMB2_CANCEL signing exclusion | **MISSING (P1-01)** | 0% |
| OPLOCK_BREAK client-ack signing | **MISSING (P1-05)** | 40% |
| Session binding wrong error code | Partial (P2-03) | 70% |

**Overall compliance estimate: ~88%**

The two confirmed P1 issues (CANCEL signing exclusion, OPLOCK_BREAK acknowledgment signing) represent relatively narrow attack surface in typical deployments but are clear spec deviations. All three major signing algorithms (HMAC-SHA256, AES-CMAC, AES-GMAC) are correctly implemented. Key derivation for all dialects matches the MS-SMB2 spec. The signing enforcement pipeline (is_sign_req → check_sign_req → STATUS_ACCESS_DENIED) is correct.
