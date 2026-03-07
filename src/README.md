# ksmbd Source Layout

This directory contains the kernel module implementation, split by subsystem:

- `core/`: core server lifecycle, auth/session glue, config/feature flags, common utilities.
- `encoding/`: ASN.1, NDR, and unicode encoding/decoding primitives.
- `fs/`: VFS integration, ACLs/oplocks, fsctl/info/notify/reparse/quota/vss helpers.
- `mgmt/`: management state for users, shares, tree connections, and ID allocators.
- `protocol/common/`: shared SMB protocol helpers.
- `protocol/smb1/`: SMB1 request handling (guarded by insecure-server config).
- `protocol/smb2/`: SMB2/SMB3 request handling, negotiate/session/tree/ioctl/read/write paths.
- `transport/`: TCP, IPC, and RDMA transport implementations.
- `include/`: exported module headers grouped by domain (`core`, `encoding`, `fs`, `protocol`, `transport`).
- `tools/`: local utility sources that are not part of the module object graph.

Build integration is defined in the top-level `Makefile` with all objects under `src/...`.
