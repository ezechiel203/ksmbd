# ksmbd Review

Reviewed areas:
- `src/transport/`
- `src/protocol/smb2/`
- `src/mgmt/`
- `src/fs/`
- `src/core/`

## Findings

### 1. High: QUIC fallback bypasses the TLS handshake and parses plaintext 1-RTT data

References:
- `src/transport/transport_quic.c:3218`
- `src/transport/transport_quic.c:3220`
- `src/transport/transport_quic.c:3287`
- `src/transport/transport_quic.c:3301`
- `src/transport/transport_quic.c:3330`
- `src/transport/transport_quic.c:3441`
- `src/transport/transport_quic.c:3467`
- `Makefile:140`

Why this matters:
- QUIC requires authenticated TLS 1.3 keys before application data is processed.
- The current code explicitly enters `QUIC_STATE_CONNECTED` when either no handshake daemon is registered or no ClientHello data was captured.
- The short-header receive path then falls back to parsing the payload as unencrypted when `app_crypto.ready` is false.
- External builds default `CONFIG_SMB_SERVER_QUIC ?= y`, so this is not a dead code path in the shipped build configuration.

Risk:
- If a QUIC listener is exposed without the userspace handshake daemon, the transport security boundary becomes optional.
- That is both a protocol-compliance failure and a real security footgun: plaintext or unauthenticated packets are treated as post-handshake traffic.

Recommendation:
- Refuse QUIC connection establishment unless the handshake daemon is registered and 1-RTT keys are installed.
- Keep the current stub mode only under an explicit developer-only Kconfig or module parameter, disabled by default.
- Reject short-header payload parsing when `app_crypto.ready` is false instead of treating it as backward-compatible plaintext.

### 2. Medium: SMB 3.1.1 still advertises persistent handles although the implementation is intentionally incomplete

References:
- `src/protocol/smb2/smb2ops.c:333`
- `src/protocol/smb2/smb2ops.c:336`
- `src/protocol/smb2/smb2ops.c:378`
- `src/protocol/smb2/smb2_create.c:863`
- `src/protocol/smb2/smb2_create.c:899`
- `src/protocol/smb2/smb2_create.c:913`
- `src/protocol/smb2/smb2_create.c:2845`
- `src/protocol/smb2/smb2_create.c:2850`

Why this matters:
- The SMB 3.1.1 init path sets `SMB2_GLOBAL_CAP_PERSISTENT_HANDLES` whenever `KSMBD_GLOBAL_FLAG_DURABLE_HANDLE` is enabled.
- The same tree documents that persistent-handle save/restore/delete is stubbed.
- The create path explicitly avoids setting `fp->is_persistent` and intentionally downgrades requests to regular durable handles.

Risk:
- Capability advertisement no longer matches server behavior.
- Clients that trust the SMB 3.1.1 negotiate response can attempt persistent-handle workflows and then observe silent downgrade or restart-time breakage.
- That is an interoperability bug at minimum, and it can turn failover/reconnect testing into false positives.

Recommendation:
- Remove `SMB2_GLOBAL_CAP_PERSISTENT_HANDLES` from `init_smb3_11_server()` until persistence is fully implemented.
- If downgrade behavior is kept, make the downgrade explicit and consistent across negotiate, create-context parsing, and reconnect handling.

## Notes

- The recent notify/session work appears materially improved relative to the usual failure modes in this area: the current tree contains explicit comments and code to avoid double-completion, per-handle watch confusion, and session-destroy deadlocks.
- I did not find a stronger current-tree issue in the changed notify code than the two transport/protocol mismatches above during this pass.
- The kernel/userspace IPC boundary would still benefit from stricter response-field validation, especially for fixed-size strings returned from userspace.
