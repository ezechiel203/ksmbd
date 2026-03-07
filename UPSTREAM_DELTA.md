# UPSTREAM_DELTA.md — Out-of-tree ksmbd vs upstream fs/smb/server/

This document tracks intentional divergences between this out-of-tree
ksmbd module and the upstream `fs/smb/server/` in the Linux kernel.

## Features unique to this fork

| Feature | Kconfig / Guard | Notes |
|---------|----------------|-------|
| SMB1/CIFS support | `CONFIG_SMB_INSECURE_SERVER` | Full SMB1 dialect, deprecated upstream |
| Apple Fruit extensions | `CONFIG_KSMBD_FRUIT` (Makefile) | macOS interop: resource forks, Finder info, Time Machine |
| Audit logging | `ksmbd_audit()` macro | pr_notice-based structured audit for auth and security events |

## Additional protocol support

- **SMB1 (NT LM 0.12)** — negotiate, session setup, tree connect, basic
  file I/O, and SMB1-to-SMB2 upgrade via dialect 0x02FF wildcard.
  Guarded by `CONFIG_SMB_INSECURE_SERVER`.
- **SMB 2.0.2** — retained for legacy client compatibility (also gated
  by `CONFIG_SMB_INSECURE_SERVER` at the Kconfig level).

## Security hardening beyond upstream

- **Auth rate limiting** — per-IP connection limits
  (`server_conf.max_ip_connections`) enforced in the TCP accept loop.
- **Structured audit trail** — `ksmbd_audit()` logs for auth failures
  (NTLMv2, Kerberos), decryption failures, and session events at
  `pr_notice` level, always visible regardless of debug flags.
- **Pre-authentication integrity** — SMB 3.1.1 preauth hash fully
  implemented with SHA-512.
- **Session encryption enforcement** — unencrypted requests on
  encrypted sessions are rejected.

## Build system differences

- Standalone out-of-tree module build with `make` / `make install`.
- DKMS packaging support (`dkms-install` / `dkms-uninstall` targets).
- Kernel version compatibility shims in `compat.c` / `compat.h` for
  API changes across kernel releases (6.1+, 6.4+, etc.).
- Conditional object lists in Makefile for optional features
  (`CONFIG_KSMBD_FRUIT`, `CONFIG_SMB_SERVER_SMBDIRECT`).

## Test infrastructure

- `test_framework/` directory with four KUnit-style test modules:
  - `smb2_end_to_end_testing.c` — full protocol flow tests
  - `integration_compatibility_testing.c` — multi-client interop
  - `apple_smb_real_client_testing.c` — Apple client simulation
  - `production_readiness_validation.c` — deployment readiness checks
- Separate `test/` directory with unit tests for individual subsystems
  (auth, VFS, oplock, credit, etc.).
- External smbtorture sweep infrastructure (`vm/sweep-smb2.sh`).

## Live reconfiguration

The out-of-tree fork documents and supports daemon reconnect for live
reconfiguration (see `server.h` state machine comments and
`handle_startup_event()` in `transport_ipc.c`).  Upstream handles this
through the standard ksmbd.mountd lifecycle.

## Tracking

This file should be updated whenever a feature is added that does not
exist in upstream `fs/smb/server/`, or when upstream changes are
back-ported.
