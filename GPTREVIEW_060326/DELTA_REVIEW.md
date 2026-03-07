# Delta Review 2026-03-06

Scope:
- Follow-up against the four findings recorded in `README.md`, `ksmbd.md`, and `ksmbd-tools.md`.
- Code changes reviewed in the current worktree only.

Disposition:
1. Fixed: QUIC no longer accepts insecure fallback handshakes or plaintext 1-RTT processing.
   - `src/transport/transport_quic.c:3215` now treats TLS 1.3 delegation as mandatory and rejects connections when no handshake daemon is registered or no Initial CRYPTO data was captured.
   - `src/transport/transport_quic.c:3283` now sends `QUIC_ERR_PROTOCOL_VIOLATION` and tears the connection down instead of entering stub `CONNECTED` mode.
   - `src/transport/transport_quic.c:3389` now drops short-header packets until 1-RTT keys exist.
   - `src/transport/transport_quic.c:3454` now rejects undersized 1-RTT packets and drops any packet that fails AEAD authentication instead of parsing it as plaintext.
   - Residual risk: this path was reviewed line-by-line but not kernel-build-verified because the local kernel headers tree is missing.

2. Fixed: persistent-handle capability advertisement is now masked consistently across SMB3 negotiation paths.
   - `src/protocol/smb2/smb2ops.c:298`, `src/protocol/smb2/smb2ops.c:341`, and `src/protocol/smb2/smb2ops.c:386` now document and enforce that `SMB2_GLOBAL_CAP_PERSISTENT_HANDLES` is not advertised while persistent-handle recovery remains incomplete/non-verifiable in the current tree.
   - This keeps negotiate-time capabilities aligned with the current backend state and prevents clients from requesting a persistence level the server cannot reliably honor.
   - Residual risk: the current source still references `ksmbd_ph_save()`, `ksmbd_ph_restore()`, and `ksmbd_ph_delete()` from other files, so persistent-handle support should be treated as incomplete until the backend is build-verified end-to-end.

3. Fixed: `ksmbd-tools` NDR helpers no longer rely on unaligned typed loads/stores or packed-member writes.
   - `ksmbd-tools/mountd/rpc.c:275` and `ksmbd-tools/mountd/rpc.c:297` now use aligned temporaries plus `memcpy()` for integer encode/decode.
   - `ksmbd-tools/mountd/rpc.c:825` reads DCE/RPC packed header integers into locals before assigning into the packed header struct.
   - `ksmbd-tools/mountd/smbacl.c:46` reads each SID subauthority into a local before assignment.
   - Result: the strict-alignment warning sites tied to the original finding no longer appear in the rebuilt `ksmbd-tools/build2` output.

4. Fixed: CIDR parsing now rejects malformed prefix strings instead of accepting `atoi()` truncation.
   - `ksmbd-tools/tools/management/share.c:967` now uses `strtol()` with `errno`, empty-string, trailing-junk, and negative-value checks.
   - Invalid suffixes such as `/8garbage` no longer parse as valid prefixes.

Validation:
- `meson test -C ksmbd-tools/build2 --print-errorlogs`: passed 27/27 after the userspace fixes.
- `make -j2 all`: blocked by missing kernel build tree `/lib/modules/6.18.9-arch1-2/build`.

Remaining observations:
- `ksmbd-tools/build2` still emits the pre-existing warning at `ksmbd-tools/tools/config_parser.c:1061` (`-Wmisleading-indentation`). That warning is outside the four reviewed findings.
- Kernel-side changes were audited directly in source but could not be compiled in this environment.
