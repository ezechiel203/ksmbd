# SMB3 Plan 01: Negotiate Contexts and Pre-Authentication Integrity

## Executive Summary

This audit covers the SMB2 NEGOTIATE path for SMB 3.0, 3.0.2, and 3.1.1 dialects as
implemented in KSMBD, measured against MS-SMB2. The implementation is substantially
correct for the core path and handles the mandatory pre-authentication integrity
mechanism end-to-end. Several issues stand out:

- The cipher selection algorithm in `decode_encrypt_ctxt()` uses first-match order
  rather than a true priority ranking, so a client that lists AES-128-CCM before
  AES-256-GCM would receive the weaker cipher even though both sides could support
  the stronger one.
- The preauth context decoder does not validate `HashAlgorithmCount`; it reads only
  `HashAlgorithms[0]` regardless of what the count field says.
- SMB 3.1.1 does not advertise `SMB2_GLOBAL_CAP_ENCRYPTION` even though
  SMB3.1.1-level encryption is fully implemented. This causes some strict clients
  to not enable encryption on 3.1.1 connections.
- `SMB2_NETNAME_NEGOTIATE_CONTEXT_ID` (0x0005) is received and silently discarded
  with no server-name validation against server configuration.
- The negotiate response hash is computed using `conn->preauth_info->Preauth_HashValue`
  even though the spec requires a per-connection (not per-session) accumulation during
  the NEGOTIATE exchange and a per-session accumulation during SESSION_SETUP. The
  implementation then seeds session-level hashing from the connection-level value
  at the point SESSION_SETUP begins, which is correct by inference but is not
  clearly separated.

Overall compliance estimate for the audited sub-area: **~82%**.

---

## Negotiate Context Audit (per context type)

### 0x0001 — SMB2_PREAUTH_INTEGRITY_CAPABILITIES (MS-SMB2 §2.2.3.1.1)

**Source**: `smb2_negotiate.c:282–299` (decode), `smb2_negotiate.c:62–72` (response build).

| Criterion | Status |
|---|---|
| Parsed? | Yes — `decode_preauth_ctxt()` line 282 |
| Only SHA-512 (0x0001) accepted? | Yes — line 294, returns `STATUS_NO_PREAUTH_INTEGRITY_HASH_OVERLAP` for anything else |
| HashAlgorithmCount validated? | **No — BUG** (see P1-01 below) |
| Salt field used? | No — salt from client is silently ignored; the server generates its own random salt in the response (line 70), which is correct per spec |
| Response context sent? | Yes — `build_preauth_ctxt()` at line 62; included unconditionally for 3.1.1 in `assemble_neg_contexts()` line 183 |
| Server salt in response random? | Yes — `get_random_bytes()` line 70 |
| HashValue initialised to zeros? | Yes — `kzalloc` of `preauth_integrity_info` at `smb2_negotiate.c:765` zero-fills the struct including `Preauth_HashValue[64]` |
| NEGOTIATE request bytes hashed? | Yes — `smb2_negotiate.c:810–812` calls `ksmbd_gen_preauth_integrity_hash()` immediately after context parsing |
| NEGOTIATE response bytes hashed? | Yes — `smb2_pdu_common.c:1209–1212` in `smb3_preauth_hash_rsp()` |
| SESSION_SETUP request bytes hashed? | Yes — `smb2_session.c:112` in `generate_preauth_hash()` |
| SESSION_SETUP response bytes hashed? | Yes — `smb2_pdu_common.c:1224,1231` in `smb3_preauth_hash_rsp()` |
| Final hash used to derive SessionKey? | Yes — `auth.c:1367–1374` uses `sess->Preauth_HashValue` as SP800-108 context field |

**Bug P1-01**: `decode_preauth_ctxt()` at line 294 reads `pneg_ctxt->HashAlgorithms`
directly, which is `HashAlgorithms[0]`. It does not read or validate
`HashAlgorithmCount` (field at offset +4 after `DataLength`). The spec (§2.2.3.1.1)
states `HashAlgorithmCount` MUST be at least 1. A crafted context with
`HashAlgorithmCount = 0` and a valid `DataLength` passes the size check at line 290
(`MIN_PREAUTH_CTXT_DATA_LEN = 6` covers the count + saltlen + one algorithm entry) but
the algorithm slot `HashAlgorithms[0]` is then read from whatever bytes follow. This
is at most an information-exposure/bypass risk, not a memory-safety issue, because the
size check still guards the read. However it violates spec and should be fixed.

---

### 0x0002 — SMB2_ENCRYPTION_CAPABILITIES (MS-SMB2 §2.2.3.1.2)

**Source**: `smb2_negotiate.c:301–341` (decode), `smb2_negotiate.c:74–82` (response build),
`smb2_negotiate.c:187–202` (assembly).

| Criterion | Status |
|---|---|
| Parsed? | Yes — `decode_encrypt_ctxt()` |
| All four ciphers recognised? | Yes — AES-128-CCM (0x0001), AES-128-GCM (0x0002), AES-256-CCM (0x0003), AES-256-GCM (0x0004) all handled at lines 331–334 |
| Priority-based selection? | **Partial — BUG** (see P1-02 below) |
| `conn->cipher_type` set? | Yes |
| Response context sent? | Yes — conditional on `conn->cipher_type != 0`, line 187 |
| Encryption actually used? | Yes — `smb3_encryption_negotiated()` at line 358 checks `conn->cipher_type` for 3.1.1 |
| SMB2_GLOBAL_CAP_ENCRYPTION advertised for 3.1.1? | **No — BUG** (see P1-03 below) |

**Bug P1-02**: `decode_encrypt_ctxt()` at lines 330–340 iterates the client's cipher
list and stops at the **first** cipher that the server knows. The client's list is
ordered by client preference (highest preference first per MS-SMB2 §2.2.3.1.2). This
means the server selects the *client's most preferred* cipher, which may be weaker than
what both sides could agree on. A correct implementation should select the
*server's most preferred* cipher from the intersection. Example: client sends
`[AES-128-CCM, AES-256-GCM]`; the server picks AES-128-CCM on the first loop
iteration and ignores AES-256-GCM. The expected behaviour per the spec is for the
server to select the strongest mutually supported algorithm (AES-256-GCM in this
case). Compare with the signing capability decoder at lines 457–471 which does perform
priority-based selection; the encryption decoder should do the same.

**Bug P1-03**: `init_smb3_11_server()` (`smb2ops.c:345–372`) does not set
`SMB2_GLOBAL_CAP_ENCRYPTION` in `smb311_server_values.capabilities`. For 3.0/3.0.2
this is handled dynamically (lines 288–291, 323–326), but for 3.1.1 the spec uses the
negotiate context mechanism instead. However, some Windows clients check the
capabilities flags even for 3.1.1 before choosing to offer encryption contexts. The
missing bit causes interoperability problems. The `smb3_encryption_negotiated()` helper
at lines 355–359 compensates by also checking `conn->cipher_type`, but the advertised
capability is wrong.

---

### 0x0003 — SMB2_COMPRESSION_CAPABILITIES (MS-SMB2 §2.2.3.1.3)

**Source**: `smb2_negotiate.c:362–419` (decode), `smb2_negotiate.c:84–94` (response build),
`smb2_negotiate.c:204–218` (assembly).

| Criterion | Status |
|---|---|
| Parsed? | Yes |
| `CompressionAlgorithmCount = 0` rejected with `STATUS_INVALID_PARAMETER`? | Yes — line 379–381 |
| Algorithm list bounds-checked? | Yes — overflow check at line 384, size check at line 389 |
| LZNT1 (0x0001) supported? | **No** — not in the selection loop |
| LZ77 (0x0002) supported? | **No** — not in the selection loop |
| LZ77+Huffman (0x0003) supported? | **No** — not in the selection loop |
| Pattern_V1 (0x0004) supported? | Yes — line 408 |
| LZ4 (0x0005, non-standard) supported? | Yes — line 400 (takes highest priority) |
| `Flags` / `SMB2_COMPRESSION_CAPABILITIES_FLAG_CHAINED` parsed? | **No** — `pneg_ctxt->Flags` is not read; `conn->compress_algorithm` does not record chain support |
| Response context sent? | Yes — conditional on `conn->compress_algorithm != SMB3_COMPRESS_NONE` |
| No-overlap case handled? | Yes — returns `STATUS_SUCCESS` with `compress_algorithm = SMB3_COMPRESS_NONE` (no context added to response), which is correct |

**P3-01**: `Flags` field (`SMB2_COMPRESSION_CAPABILITIES_FLAG_CHAINED = 0x00000001`)
from the client's context is silently ignored. Chained compression support per
MS-SMB2 §2.2.3.1.3 must be reflected in the response. The `build_compress_ctxt()`
function at line 84 hardcodes `pneg_ctxt->Flags = 0` regardless.

**P2-01**: LZNT1, LZ77, and LZ77+Huffman are defined in the MS-SMB2 spec as the base
compression algorithms. None of them are implemented; the server only knows Pattern_V1
and the non-standard LZ4. For interoperability with Windows clients that only offer
LZNT1/LZ77, negotiation falls through to `conn->compress_algorithm = SMB3_COMPRESS_NONE`.

---

### 0x0005 — SMB2_NETNAME_NEGOTIATE_CONTEXT_ID (MS-SMB2 §2.2.3.1.4)

**Source**: `smb2_negotiate.c:627–629`.

| Criterion | Status |
|---|---|
| Parsed? | Recognised — context type matched at line 627, then `ksmbd_debug()` only |
| ServerName validated against server config? | **No** |
| No response context sent (correct)? | Yes — no response context is added, which is correct per spec |

**P2-02**: The spec (§3.3.5.2.4, step 2) states the server SHOULD validate the
`NetName` field against the server's network address to guard against target-name
confusion attacks. KSMBD logs the context's presence but does not extract or compare
the name.

---

### 0x0006 — SMB2_TRANSPORT_CAPABILITIES (MS-SMB2 §2.2.3.1.5)

**Source**: `smb2_negotiate.c:486–499` (decode), `smb2_negotiate.c:131–140` (response build),
`smb2_negotiate.c:265–276` (assembly).

| Criterion | Status |
|---|---|
| Parsed? | Yes — `decode_transport_cap_ctxt()` at line 486 |
| `SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY` flag processed? | Yes — `conn->transport_secured = true` at line 497 |
| Response context sent? | Yes — conditional on `conn->transport_secured`, line 265 |
| Server flags in response correct? | Yes — `SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY` hardcoded in response (line 139) |

No bugs found here. Implementation is correct for the defined scope.

---

### 0x0007 — SMB2_RDMA_TRANSFORM_CAPABILITIES (MS-SMB2 §2.2.3.1.6)

**Source**: `smb2_negotiate.c:501–542` (decode), `smb2_negotiate.c:108–129` (response build),
`smb2_negotiate.c:248–263` (assembly).

| Criterion | Status |
|---|---|
| Parsed? | Yes — `decode_rdma_transform_ctxt()` at line 501 |
| `TransformCount = 0` handled? | Yes — early return at line 516 (logs error, `rdma_transform_count` stays 0) |
| All defined IDs recognised? | Yes — NONE (0x0000), ENCRYPTION (0x0001), SIGNING (0x0002) at lines 531–533 |
| Array overflow guarded? | Yes — `ARRAY_SIZE(conn->rdma_transform_ids)` check at line 534 |
| Response sent? | Yes — conditional on `conn->rdma_transform_count > 0`, line 248 |

**P4-01**: `decode_rdma_transform_ctxt()` at line 516 treats `TransformCount = 0` as
an error and logs it, but does not return an error code to the caller. The spec does
not explicitly mandate rejection for `TransformCount = 0` (unlike the signing and
preauth contexts), but it is an unusual state since there is no point sending the
context with no transforms. The current behaviour (silent ignore) is benign.

---

### 0x0008 — SMB2_SIGNING_CAPABILITIES (MS-SMB2 §2.2.3.1.7)

**Source**: `smb2_negotiate.c:421–484` (decode), `smb2_negotiate.c:96–106` (response build),
`smb2_negotiate.c:232–246` (assembly).

| Criterion | Status |
|---|---|
| Parsed? | Yes — `decode_sign_cap_ctxt()` at line 421 |
| `SigningAlgorithmCount = 0` rejected? | Yes — line 439 returns `STATUS_INVALID_PARAMETER` |
| All three algorithms recognised? | Yes — HMAC-SHA256 (0x0000), AES-CMAC (0x0001), AES-GMAC (0x0002) at lines 460–465 |
| Priority-based selection (best of server's preference)? | Yes — priority 0/1/2 assigned at lines 460–469; `best_priority` tracking selects the strongest known algo |
| Fallback when no common algo? | Yes — falls back to AES-CMAC at line 481 (but see P2-03) |
| `conn->signing_negotiated` set? | Yes — line 473 |
| `conn->signing_algorithm` set from this? | Yes — line 477 |
| Response context sent? | Yes — conditional on `conn->signing_negotiated`, line 232 |

**P2-03**: The fallback path at line 479–481 sets `conn->signing_algorithm =
SIGNING_ALG_AES_CMAC` even when the client's list contained only `HMAC-SHA256` and
did not list AES-CMAC. Per MS-SMB2 §3.3.5.4, if no overlap exists the connection
should fail, not silently downgrade. The comment says "no common algorithm, fall back
to AES-CMAC" but `best_priority` will be -1 only when none of the three known
algorithms appears in the client list, which in practice means the client sent unknown
future algorithm IDs. The fallback is a conservative interop measure, but it violates
the spec's MUST-reject requirement.

---

## Pre-Authentication Integrity Audit

**Spec reference**: MS-SMB2 §3.3.5.2.4 (NEGOTIATE), §3.3.5.5.4 / §3.3.5.5.3
(SESSION_SETUP), §3.2.5.5.3 (client-side, for reference).

### Initialisation

`kzalloc(sizeof(struct preauth_integrity_info), ...)` at `smb2_negotiate.c:765` zero-
fills the 64-byte `Preauth_HashValue` array before any hashing begins. This matches
the spec requirement to initialise the hash accumulator to a zero byte array.

The structure is connection-scoped (`conn->preauth_info`) for the NEGOTIATE phase,
then copied per-session at the start of SESSION_SETUP via `alloc_preauth_hash()`
at `smb2_session.c:61–76`, which calls `kmemdup(conn->preauth_info->Preauth_HashValue,
PREAUTH_HASHVALUE_SIZE, ...)`.

### Hash computation function

`ksmbd_gen_preauth_integrity_hash()` at `auth.c:1450` computes:

```
new_hash = SHA-512(old_hash || message_bytes)
```

where `old_hash` is the previous 64-byte accumulator and `message_bytes` is the
raw SMB2 PDU starting at `ProtocolId` (excluding the 4-byte RFC-1002 length prefix).
This matches the iterative hash construction in MS-SMB2 §3.3.5.2.4.

### Per-phase coverage

| Phase | Request hashed? | Response hashed? | Source |
|---|---|---|---|
| NEGOTIATE | Yes | Yes | `smb2_negotiate.c:810`, `smb2_pdu_common.c:1209` |
| SESSION_SETUP (each round-trip) | Yes | Yes | `smb2_session.c:112`, `smb2_pdu_common.c:1224,1231` |

### Use of final hash in key derivation

`ksmbd_gen_smb311_signingkey()` and `ksmbd_gen_smb311_encryptionkey()` in
`auth.c:~1360–1447` use `sess->Preauth_HashValue` (or `preauth_sess->Preauth_HashValue`
for multi-channel binding) as the SP800-108 context input, matching MS-SMB2 §3.3.5.5.3
step 9.

### Identified issue — hash accumulation uses connection-level buffer through NEGOTIATE

`smb2_negotiate.c:810–812` hashes the NEGOTIATE *request* into
`conn->preauth_info->Preauth_HashValue`. Then `smb2_pdu_common.c:1209–1212` hashes
the NEGOTIATE *response* into the same buffer. This is correct for the single-
negotiate scenario. However, if a second NEGOTIATE arrives on the same connection, the
code at `smb2_negotiate.c:691–700` disconnects the connection (setting
`send_no_response = 1`), so the double-hash risk does not arise.

**P3-02**: The `alloc_preauth_hash()` call at `smb2_session.c:70` copies
`conn->preauth_info->Preauth_HashValue` into `sess->Preauth_HashValue`. This happens
at the start of the first SESSION_SETUP round-trip, at which point the connection-
level hash already covers the NEGOTIATE request and response. Per spec, the session-
level hash initialises from the connection-level value after NEGOTIATE completes, so
timing is correct. However, if a session is created before NEGOTIATE completes
(which cannot happen given state machine checks), the session would start with a
zero hash. The current state machine (`KSMBD_SESS_NEED_SETUP` gated by `ksmbd_conn_good()`)
prevents this, but there is no explicit assertion.

---

## Dialect Negotiation Correctness

### SMB1-to-SMB2 upgrade

`smb_common.c:686–704`: when an SMB1 NEGOTIATE arrives containing an SMB2-compatible
dialect string, `__smb2_negotiate()` (line 647) detects `conn->dialect >= SMB20_PROT_ID`
and the code responds with an SMB2 NEGOTIATE response using wildcard dialect 0x02FF
(`SMB2X_PROT_ID`). This forces the client to send a follow-up SMB2 NEGOTIATE for
proper dialect selection. This matches the MS-SMB2 §3.3.5.3 multi-protocol upgrade
procedure.

### Wildcard dialect (0x02FF) handling

`smb2_negotiate.c:858–866`: `SMB2X_PROT_ID` and `BAD_PROT_ID` both fall into the
`default` branch and return `STATUS_NOT_SUPPORTED`. This is reached when the client
sends a native SMB2 NEGOTIATE with only the wildcard 0x02FF dialect. This is the
correct rejection behaviour per MS-SMB2 §3.3.5.4 step 1 bullet: the server MUST NOT
proceed with only the wildcard dialect in an SMB2 NEGOTIATE.

### Dialect selection algorithm

`ksmbd_lookup_dialect_by_id()` at `smb_common.c:297–322` iterates the server's
protocol table from highest index to lowest, and within each server-side entry scans
the client dialect list. This correctly selects the highest mutually supported dialect.

### SecurityMode — SIGNING_REQUIRED enforcement

`smb2_negotiate.c:906–921`:

- If `server_conf.signing == KSMBD_CONFIG_OPT_MANDATORY`: sets `SIGNING_REQUIRED` in
  response and `conn->sign = true`. Correct.
- If `KSMBD_CONFIG_OPT_AUTO`: enables signing if the client advertises
  `SIGNING_ENABLED`. This is a conservative correct choice.
- If `KSMBD_CONFIG_OPT_DISABLED` and client sends `SIGNING_REQUIRED`: sets
  `conn->sign = true`. Correct — server must honour client's SIGNING_REQUIRED
  per MS-SMB2 §3.3.5.4.

**P2-04**: When `server_conf.signing == KSMBD_CONFIG_OPT_DISABLED` and the client
sends `SIGNING_REQUIRED`, the server sets `conn->sign = true` but continues normally.
Strictly speaking the server's own `SecurityMode` response word should still have
`SIGNING_REQUIRED` cleared (the server does not *require* signing), and only the
session-level signing decision matters. The current code at line 903 sets
`rsp->SecurityMode = SMB2_NEGOTIATE_SIGNING_ENABLED_LE` and never adds `SIGNING_REQUIRED`
to the response in the DISABLED case, which is correct. `conn->sign = true` is set to
honour the client's requirement. No bug here; noted for clarity.

### NegotiateContextOffset padding

`assemble_neg_contexts()` at line 191 uses `round_up(ctxt_size, 8)` between consecutive
context entries. The initial offset is `OFFSET_OF_NEG_CONTEXT = 0xe0 = 224`, which is:
header(64) + negotiate_response_body(64) + GSS(96) = 224. This is 8-byte aligned.
The spec requires 8-byte padding between contexts (§2.2.3.1), which the code correctly
applies.

**P1-04**: The size arithmetic for `build_sign_cap_ctxt()` at line 100–102 is:
```c
cpu_to_le16((sizeof(struct smb2_signing_capabilities) + 2)
            - sizeof(struct smb2_neg_context));
```
`smb2_signing_capabilities` includes the header fields from `smb2_neg_context`
(ContextType + DataLength + Reserved = 8 bytes) plus `SigningAlgorithmCount` (2 bytes)
plus a flexible array. The `+ 2` accounts for one `SigningAlgorithms[0]` entry.
`DataLength` should be the payload length excluding the 8-byte header, so:
`(struct_size - 8 + 2) - 0 = struct_size - 6`. Given that
`sizeof(smb2_signing_capabilities)` with an empty flexible array is 10 bytes
(8-byte header + 2-byte count), the DataLength evaluates to `(10 + 2) - 8 = 4`.
This is correct for one algorithm entry (2 bytes count + 2 bytes algorithm = 4).
The calculation is convoluted but produces the right number.

Similarly, `build_encrypt_ctxt()` at line 78: `DataLength = 4` for one cipher
(2-byte count + 2-byte cipher). Correct.

---

## Capability Advertisement Gaps

Based on `smb2ops.c` `smb311_server_values` (line 123–149) and the conditional logic
in `init_smb3_11_server()` (lines 345–372):

| Capability | Advertised for SMB3.1.1? | Implementation exists? | Assessment |
|---|---|---|---|
| `SMB2_GLOBAL_CAP_LARGE_MTU` (0x04) | Yes (base) | Yes | Correct |
| `SMB2_GLOBAL_CAP_NOTIFICATIONS` (0x80) | Yes (base) | Partial — `smb2_notify()` implements Change Notify; server-to-client push notifications (SMB2 CHANGE_NOTIFY unsolicited) not fully implemented | P3-03: advertised but not fully supported |
| `SMB2_GLOBAL_CAP_LEASING` (0x02) | Conditional — `KSMBD_GLOBAL_FLAG_SMB2_LEASES` | Yes | Correct |
| `SMB2_GLOBAL_CAP_DIRECTORY_LEASING` (0x20) | Conditional — `KSMBD_GLOBAL_FLAG_SMB2_LEASES` | Partial | Correct conditional |
| `SMB2_GLOBAL_CAP_MULTI_CHANNEL` (0x08) | Conditional — `KSMBD_GLOBAL_FLAG_SMB3_MULTICHANNEL` | Partial | Correct conditional |
| `SMB2_GLOBAL_CAP_PERSISTENT_HANDLES` (0x10) | Conditional — `KSMBD_GLOBAL_FLAG_DURABLE_HANDLE` | Partial | Correct conditional |
| `SMB2_GLOBAL_CAP_DFS` (0x01) | Conditional — `ksmbd_dfs_enabled()` | Partial | Correct conditional |
| `SMB2_GLOBAL_CAP_ENCRYPTION` (0x40) | **Never for SMB3.1.1** | Yes — via cipher_type | **P1-03 (see above)** |

**P1-03 (detail)**: `smb311_server_values.capabilities` is `SMB2_GLOBAL_CAP_LARGE_MTU |
SMB2_GLOBAL_CAP_NOTIFICATIONS`. There is no code path in `init_smb3_11_server()` that
adds `SMB2_GLOBAL_CAP_ENCRYPTION`. For 3.0 and 3.0.2, `SMB2_GLOBAL_CAP_ENCRYPTION`
is the primary signal. For 3.1.1, MS-SMB2 §3.3.5.4 step 4 states: "If the server
implements the SMB 3.1.1 dialect, Connection.CipherId MUST be set" (from the
negotiate context), and the capability flag is not required. However, Windows servers
do advertise it for compatibility. Its absence causes some clients to not attempt
encryption.

---

## Confirmed Bugs (P1)

### P1-01 — HashAlgorithmCount not validated in decode_preauth_ctxt()

- **File:Line**: `src/protocol/smb2/smb2_negotiate.c:282–299`
- **Symptom**: A client sending `HashAlgorithmCount = 0` with a valid `DataLength >= 6`
  passes the size check but then reads `HashAlgorithms[0]` which falls within padding
  bytes. If those bytes happen to be `0x0001` (SHA-512 in LE), the context is
  accepted. If they are not, `STATUS_NO_PREAUTH_INTEGRITY_HASH_OVERLAP` is returned.
  No memory-safety issue, but the count field is ignored entirely.
- **Spec ref**: MS-SMB2 §2.2.3.1.1: `HashAlgorithmCount` (2 bytes) MUST be >= 1.
- **Fix**: After the size check, read `le16_to_cpu(pneg_ctxt->HashAlgorithmCount)`,
  return `STATUS_INVALID_PARAMETER` if it is 0, and iterate up to
  `HashAlgorithmCount` entries looking for 0x0001.

### P1-02 — Cipher selection uses client-preference order, not server-preference

- **File:Line**: `src/protocol/smb2/smb2_negotiate.c:330–340`
- **Symptom**: The server selects the *first* cipher in the client's list that it
  recognises. If the client lists `[AES-128-CCM, AES-256-GCM]`, the server selects
  AES-128-CCM even though AES-256-GCM is stronger and both sides support it.
- **Spec ref**: MS-SMB2 §3.3.5.2.5.2 step 2: "The server MUST set
  Connection.CipherId to the value in the Ciphers array that is preferred by the
  server." This means server preference, not client preference.
- **Fix**: Apply the same priority-ranking pattern used in `decode_sign_cap_ctxt()`
  (lines 457–471): assign a server-side priority to each known cipher (e.g.,
  AES-256-GCM=3, AES-256-CCM=2, AES-128-GCM=1, AES-128-CCM=0) and iterate the
  client list tracking the best mutually-preferred cipher.

### P1-03 — SMB2_GLOBAL_CAP_ENCRYPTION not advertised for SMB 3.1.1

- **File:Line**: `src/protocol/smb2/smb2ops.c:123–149` (`smb311_server_values`);
  `src/protocol/smb2/smb2ops.c:345–372` (`init_smb3_11_server`)
- **Symptom**: Windows clients observing the capability bits may not attempt to
  negotiate encryption contexts if `SMB2_GLOBAL_CAP_ENCRYPTION` is absent in the
  NEGOTIATE response, even when the server correctly generates `SMB2_ENCRYPTION_CAPABILITIES`
  context responses.
- **Spec ref**: MS-SMB2 §2.2.4 (NEGOTIATE Response Capabilities): the bit is defined
  as "Applicable for 3.0, 3.0.2, 3.1.1". Advertising it is not required for 3.1.1
  but is recommended for compatibility.
- **Fix**: In `init_smb3_11_server()`, add conditional logic matching the 3.0/3.0.2
  pattern: set `SMB2_GLOBAL_CAP_ENCRYPTION` if encryption is not globally disabled.

### P1-04 — (Resolved — see Dialect Negotiation section)

The `NegotiateContextCount` field in the response is set by `assemble_neg_contexts()`
at line 278 to the count of contexts added. The `NegotiateContextOffset` is hardcoded
to `OFFSET_OF_NEG_CONTEXT = 0xe0` at `smb2_negotiate.c:813`. The calculation
0xe0 = 64 (SMB2 header) + 64 (negotiate response body) + 96 (AUTH_GSS_LENGTH) + 0
(AUTH_GSS_PADDING) is correct and 8-byte aligned. No bug.

---

## Missing Features (P2)

### P2-01 — Standard compression algorithms LZNT1, LZ77, LZ77+Huffman not implemented

- **File:Line**: `src/protocol/smb2/smb2_negotiate.c:399–415`
- **Impact**: Connections with Windows clients that do not support LZ4 or Pattern_V1
  will never compress. Windows 10/11 typically offer LZNT1 and LZ77+Huffman.
- **Spec ref**: MS-SMB2 §2.2.3.1.3

### P2-02 — SMB2_NETNAME_NEGOTIATE_CONTEXT_ID not validated

- **File:Line**: `src/protocol/smb2/smb2_negotiate.c:627–629`
- **Impact**: No target-name confusion detection. An MITM or misconfigured client
  could negotiate with a server it did not intend to reach.
- **Spec ref**: MS-SMB2 §3.3.5.2.4 step 2 (SHOULD validate)

### P2-03 — Signing algorithm fallback when no overlap silently uses AES-CMAC

- **File:Line**: `src/protocol/smb2/smb2_negotiate.c:479–481`
- **Impact**: Client sends unknown future signing algorithms (e.g., algorithm IDs > 2);
  server does not reject the negotiate but silently uses AES-CMAC which the client
  did not advertise.
- **Spec ref**: MS-SMB2 §3.3.5.4: if no common signing algorithm, the server
  MUST return `STATUS_NOT_SUPPORTED`.

---

## Partial Implementations (P3)

### P3-01 — Compression chaining flag ignored

- **File:Line**: `src/protocol/smb2/smb2_negotiate.c:84–94` (`build_compress_ctxt`),
  `src/protocol/smb2/smb2_negotiate.c:362–419` (decoder does not read `Flags`)
- **Impact**: Server never advertises or tracks chained-compression support. The
  `smb2_compress.c` implementation may or may not handle chained messages; the
  negotiate path does not coordinate this.
- **Spec ref**: MS-SMB2 §2.2.3.1.3 `Flags` field

### P3-02 — No explicit assertion that preauth hash is seeded after NEGOTIATE completes

- **File:Line**: `src/protocol/smb2/smb2_session.c:61–76`
- **Impact**: Timing dependency between `conn->preauth_info->Preauth_HashValue` being
  fully computed and `alloc_preauth_hash()` copying it. State machine guards prevent
  the race, but there is no assertion or static analysis annotation.
- **Spec ref**: MS-SMB2 §3.3.5.5.3 step 9

### P3-03 — SMB2_GLOBAL_CAP_NOTIFICATIONS advertised but server-initiated notifications not fully implemented

- **File:Line**: `src/protocol/smb2/smb2ops.c:127`
- **Impact**: The capability bit (0x80) is set in `smb311_server_values.capabilities`,
  which per MS-SMB2 §2.2.4 indicates the server supports sending asynchronous
  SMB2_SERVER_TO_CLIENT_NOTIFICATION PDUs. The `smb2_notify()` handler processes
  client-initiated CHANGE_NOTIFY requests, but there is no code path that generates
  unsolicited server-to-client notification PDUs (command 0x0013).
- **Spec ref**: MS-SMB2 §2.2.44

---

## Low Priority (P4)

### P4-01 — RDMA TransformCount = 0 logged as error but not rejected

- **File:Line**: `src/protocol/smb2/smb2_negotiate.c:516–519`
- **Impact**: Benign; context is silently ignored. The spec does not require rejection
  for this case.

### P4-02 — ServerGUID is zeroed in NEGOTIATE response

- **File:Line**: `src/protocol/smb2/smb2_negotiate.c:891`
- **Impact**: `memset(rsp->ServerGUID, 0, SMB2_CLIENT_GUID_SIZE)`. The comment says
  "not used by client for identifying server", but per MS-SMB2 §2.2.4 the field is a
  server GUID. It is used by multichannel and some RDM scenarios. A fixed-zero GUID
  may cause multichannel to fail since the client uses this to correlate channels to
  the same server.
- **Spec ref**: MS-SMB2 §3.3.5.4 step 9: ServerGUID MUST be set to a stable per-server GUID.

### P4-03 — Duplicate context detection uses conn->cipher_type as presence flag

- **File:Line**: `src/protocol/smb2/smb2_negotiate.c:605–608`
- **Impact**: For ENCRYPTION_CAPABILITIES, duplicate detection checks `if
  (conn->cipher_type)`. If `decode_encrypt_ctxt()` set `conn->cipher_type = 0`
  (no common cipher found), a second ENCRYPTION_CAPABILITIES context in the request
  would not be detected as a duplicate. Correct behaviour would be to track a
  boolean `encrypt_ctxt_seen` as done for `compress_ctxt_seen` at line 553.

---

## Compliance Estimate

| Area | Score | Notes |
|---|---|---|
| Preauth integrity context (0x0001) | 90% | HashAlgorithmCount not checked (P1-01) |
| Encryption capabilities (0x0002) | 70% | Wrong cipher selection order (P1-02), missing GAP_ENCRYPTION bit (P1-03) |
| Compression capabilities (0x0003) | 60% | Only 2 of 5 spec algorithms; chaining flag ignored |
| NetName context (0x0005) | 40% | Parsed, no response (correct), but no validation |
| Transport capabilities (0x0006) | 100% | Full |
| RDMA transform capabilities (0x0007) | 90% | Minor: TransformCount=0 handling |
| Signing capabilities (0x0008) | 85% | No-overlap fallback should reject |
| Pre-auth integrity accumulation | 95% | Fully functional; minor assertion gap |
| Dialect negotiation | 90% | ServerGUID zeroed (P4-02) |
| Capability advertisement | 80% | NOTIFICATIONS partially false; ENCRYPTION missing for 3.1.1 |

**Overall estimate: ~82%**
