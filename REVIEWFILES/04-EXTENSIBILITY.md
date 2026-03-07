# KSMBD Extensibility and Architecture Review

**Review Date**: 2026-02-22
**Reviewer**: Senior Linux Kernel Architect
**Scope**: Full codebase extensibility audit of ksmbd in-kernel SMB3 server
**Repository**: `/home/ezechiel203/ksmbd/`

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Code Organization Assessment](#2-code-organization-assessment)
3. [Extension Points Analysis](#3-extension-points-analysis)
4. [Coupling Analysis](#4-coupling-analysis)
5. [Modular Design Opportunities](#5-modular-design-opportunities)
6. [ABI/API Design Principles](#6-abiapi-design-principles)
7. [Configuration Architecture](#7-configuration-architecture)
8. [Testing Architecture](#8-testing-architecture)
9. [Kernel Integration Quality](#9-kernel-integration-quality)
10. [Consolidated Recommendations](#10-consolidated-recommendations)

---

## 1. Executive Summary

The ksmbd codebase exhibits a functional but architecturally inconsistent approach to extensibility. There are areas of genuine elegance -- the `smb_version_ops`/`smb_version_values` pattern, the transport ops abstraction, and the nascent `CONFIG_KSMBD_FRUIT` conditional compilation model -- alongside significant structural weaknesses that impede extension, maintainability, and modularization.

**Key findings:**

- **Monolithic protocol handler**: `smb2pdu.c` is approximately 10,000+ lines with deeply embedded switch-case dispatch for IOCTL, QUERY_INFO, and SET_INFO, making it the single largest barrier to extensibility.
- **Inconsistent abstraction depth**: The transport layer has clean ops-table-based polymorphism; the VFS layer is a thin wrapper with substantial leakage; the authentication layer mixes concerns.
- **Structural coupling through shared state**: The `ksmbd_conn`, `ksmbd_work`, and `ksmbd_session` structs are accessed pervasively, creating a "god object" pattern that would break dozens of files on any structural change.
- **No registration-based dispatch**: All command handling, FSCTL dispatch, and info-level processing is done via compile-time switch statements rather than runtime-registerable handlers.
- **Good compile-time gating model**: `CONFIG_KSMBD_FRUIT`, `CONFIG_SMB_INSECURE_SERVER`, and `CONFIG_SMB_SERVER_SMBDIRECT` demonstrate a working pattern for feature isolation, but the pattern is not universally applied.

**Architecture Grade: C+**

The codebase works and has some good patterns, but its extensibility story is ad-hoc rather than designed. Adding a new protocol version, FSCTL, info level, create context, or transport requires touching the core monolith rather than registering against a well-defined extension API.

---

## 2. Code Organization Assessment

### 2.1 Module Dependency Map

#### Source file -> Header dependencies (non-trivial relationships)

| Source File | Key Header Dependencies | Coupling Level |
|---|---|---|
| `smb2pdu.c` | glob, smb2pdu, smbfsctl, oplock, smbacl, auth, asn1, connection, transport_ipc, transport_rdma, vfs, vfs_cache, misc, server, smb_common, smbstatus, ksmbd_work, mgmt/*, ndr, transport_tcp, smb2fruit, compat | **EXTREME** (20+ headers) |
| `server.c` | glob, oplock, misc, server, smb_common, smbstatus, connection, transport_ipc, mgmt/user_session, crypto_ctx, auth, smb2fruit | HIGH |
| `connection.c` | server, smb_common, smb1pdu(conditional), mgmt/ksmbd_ida, connection, transport_tcp, transport_rdma, smb2fruit | HIGH |
| `vfs.c` | glob, oplock, connection, vfs, vfs_cache, smbacl, ndr, auth, misc, smb_common, smb2fruit, mgmt/* | HIGH |
| `oplock.c` | glob, oplock, smb_common, smb1pdu(conditional), smbstatus, connection, server, smb2fruit, mgmt/* | HIGH |
| `auth.c` | auth, glob, server, smb_common, connection, mgmt/user_session, mgmt/user_config, crypto_ctx, transport_ipc | MEDIUM |
| `transport_tcp.c` | smb_common, server, auth, connection, transport_tcp | LOW |
| `transport_ipc.c` | vfs_cache, transport_ipc, server, smb_common, mgmt/*, connection, transport_tcp, transport_rdma | MEDIUM |
| `smb2fruit.c` | smb2fruit, smb_common, connection, server, ksmbd_netlink, oplock | LOW-MEDIUM |

#### Key observations:

1. **`smb2pdu.c` is the gravity well**: It depends on nearly every other header in the project. This is the single worst coupling point. Any change to any subsystem potentially requires retesting the entire PDU handler.

2. **Bidirectional dependencies exist**: `vfs.c` includes `smb_common.h`, and `smb_common.c` uses VFS-related types. `connection.c` includes `smb2fruit.h`, and `smb2fruit.c` includes `connection.h`.

3. **Management layer is relatively clean**: The `mgmt/` directory has reasonable isolation. `share_config.c` only depends on sibling files + `../connection.h`, `../transport_ipc.h`, `../misc.h`.

4. **`glob.h` is a pollution vector**: Used as a catch-all include that pulls in debug macros and miscellaneous definitions. Nearly every `.c` file includes it.

### 2.2 Circular Dependencies

| Cycle | Files Involved | Severity |
|---|---|---|
| Connection <-> SMB Common | `connection.h` defines `ksmbd_conn` which embeds `smb_version_ops*` from `smb_common.h`; `smb_common.c` includes `connection.h` | **Medium** -- functional but architecturally tangled |
| VFS <-> Oplock | `vfs.c` includes `oplock.h`; `oplock.c` calls VFS functions indirectly through `ksmbd_file` | **Low** -- mostly unidirectional |
| Server <-> Connection | `server.c` initializes connection infrastructure; `connection.c` checks `server_conf` state | **Medium** -- shared global state |
| SMB2PDU <-> Everything | `smb2pdu.c` depends on all subsystems; many subsystems define types consumed by `smb2pdu.c` | **High** -- the monolith problem |

- **Current state**: Circular dependencies exist but are managed through forward declarations and careful include ordering.
- **Issue**: The cycles make it impossible to compile or test subsystems independently.
- **Proposal**: Introduce a formal dependency DAG with layered headers (see Section 6).
- **Impact**: Enables independent compilation units and unit testing.
- **Effort**: L
- **Risk**: Requires significant header refactoring that could introduce build regressions.
- **Priority**: P1

### 2.3 Abstraction Layer Assessment

#### VFS Layer (`vfs.c/h`): Thin Wrapper with Significant Leakage

- **Current state**: `vfs.h` declares ~40 functions that map almost 1:1 to Linux VFS operations (e.g., `ksmbd_vfs_read()`, `ksmbd_vfs_write()`, `ksmbd_vfs_mkdir()`). The abstraction adds error handling, permission overrides (via `ksmbd_override_fsids`), and some SMB-specific logic (stream handling, xattr management).
- **Issue**: The VFS abstraction is **leaky in both directions**:
  - **Upward leakage**: `smb2pdu.c` directly calls `vfs_statfs()`, `kern_path()`, and other VFS functions, bypassing the `ksmbd_vfs_*` layer entirely. The QUERY_INFO filesystem handler at line ~5997 of `smb2pdu.c` calls `kern_path(share->path, ...)` directly.
  - **Downward leakage**: `vfs.c` has SMB-specific knowledge -- it knows about `ksmbd_share_config`, tree connections, and stream names. A proper VFS abstraction would not know about SMB semantics.
  - **Kernel version coupling**: `vfs.c` is riddled with `#if LINUX_VERSION_CODE` conditionals (at least 10 such blocks), mixing version compatibility with business logic.
- **Proposal**: Split into three layers:
  1. `ksmbd_vfs_ops.h` -- abstract VFS operations interface (could be backed by any filesystem)
  2. `ksmbd_vfs_linux.c` -- Linux VFS implementation of the ops interface
  3. `ksmbd_vfs_compat.c` -- version-compatibility shims (already partially done with `compat.c`)
- **Impact**: Clean backend substitution (e.g., testing with mock VFS, FUSE-based backends), better testability.
- **Effort**: XL
- **Risk**: Performance regression from additional indirection; significant refactoring surface area.
- **Priority**: P2

#### Transport Layer (`transport_tcp.c`, `transport_rdma.c`): Good Abstraction

- **Current state**: The `ksmbd_transport_ops` struct provides a clean polymorphic interface:
  ```c
  struct ksmbd_transport_ops {
      int (*prepare)(struct ksmbd_transport *t);
      void (*disconnect)(struct ksmbd_transport *t);
      void (*shutdown)(struct ksmbd_transport *t);
      int (*read)(...);
      int (*writev)(...);
      int (*rdma_read)(...);
      int (*rdma_write)(...);
      void (*free_transport)(struct ksmbd_transport *kt);
  };
  ```
- **Issue**: The `rdma_read`/`rdma_write` methods in the ops table are RDMA-specific, violating the abstraction. TCP transport stubs simply set these to NULL. The base `ksmbd_transport` struct is embedded in transport-specific structs (`tcp_transport`, `smbd_transport`) via composition, which is the correct kernel pattern.
- **Proposal**: Move `rdma_read`/`rdma_write` to a secondary ops table (`ksmbd_rdma_ops`) registered only when RDMA is active. This would make the base transport ops truly transport-agnostic.
- **Impact**: Cleaner abstraction; easier to add new transport types (e.g., QUIC, io_uring-based).
- **Effort**: S
- **Risk**: Low -- the RDMA operations are already checked for NULL before invocation.
- **Priority**: P2

#### Protocol Dispatch Layer: Functional but Inflexible

- **Current state**: Protocol dispatch works through a two-level system:
  1. `conn->ops` (type `smb_version_ops*`) -- version-specific operations (signing, encryption, header management)
  2. `conn->cmds` (type `smb_version_cmds[]`) -- command dispatch table indexed by command number
- **Issue**: The dispatch tables are compile-time static arrays. There is exactly one command table (`smb2_0_server_cmds`) shared across all SMB2/3 versions. Adding or overriding a command handler requires modifying the static table or adding a new one.
- **Proposal**: See Section 3.2 for detailed analysis.
- **Priority**: P1

---

## 3. Extension Points Analysis

### 3.1 `smb_version_ops` / `smb_version_values` Pattern

#### Current State

The `smb_version_ops` struct defines 15 function pointers covering the full protocol lifecycle:

```c
struct smb_version_ops {
    u16 (*get_cmd_val)(struct ksmbd_work *);
    int (*init_rsp_hdr)(struct ksmbd_work *);
    void (*set_rsp_status)(struct ksmbd_work *, __le32);
    int (*allocate_rsp_buf)(struct ksmbd_work *);
    int (*set_rsp_credits)(struct ksmbd_work *);
    int (*check_user_session)(struct ksmbd_work *);
    int (*get_ksmbd_tcon)(struct ksmbd_work *);
    bool (*is_sign_req)(struct ksmbd_work *, unsigned int);
    int (*check_sign_req)(struct ksmbd_work *);
    void (*set_sign_rsp)(struct ksmbd_work *);
    int (*generate_signingkey)(...);
    int (*generate_encryptionkey)(...);
    bool (*is_transform_hdr)(void *);
    int (*decrypt_req)(struct ksmbd_work *);
    int (*encrypt_resp)(struct ksmbd_work *);
};
```

Three concrete instances exist:
- `smb2_0_server_ops` -- SMB 2.0/2.1 (no encryption/signing key generation)
- `smb3_0_server_ops` -- SMB 3.0/3.0.2 (adds encryption, uses AES-CMAC signing)
- `smb3_11_server_ops` -- SMB 3.1.1 (different key derivation)

The `smb_version_values` struct holds per-version numeric parameters (max sizes, capabilities, header sizes).

#### Assessment

**Strengths:**
- Clean function-pointer-based polymorphism.
- Per-version values are properly separated from logic.
- Values are `kmemdup`'d per connection, allowing per-connection runtime modification (e.g., capability negotiation).

**Weaknesses:**
- The ops struct mixes concerns: protocol framing (header init, buffer alloc), security (signing, encryption), and session management (user session check, tcon lookup) are all in one struct.
- The `smb_version_cmds` table is shared across versions -- `smb2_0_server_cmds` is used for ALL SMB2/3 versions. This means there is no way to have version-specific command implementations without runtime branching inside the handler.
- No mechanism for registering new ops at runtime (e.g., from a loadable sub-module).

#### What would it take to add SMB 3.2?

**Current effort required:**
1. Add `SMB32_PROT_ID`, `SMB32_PROT` constants to `smb_common.h` -- trivial.
2. Add `smb32_server_values` instance in `smb2ops.c` -- copy + modify, trivial.
3. Add `smb32_server_ops` if signing/encryption changes -- moderate, possible new ops functions.
4. Add `init_smb3_2_server()` in `smb2ops.c` -- trivial, pattern exists.
5. Add protocol entry in `smb2_protos[]` in `smb_common.c` -- trivial.
6. If new commands exist: modify `smb2_0_server_cmds` table or create a new one -- moderate.
7. If new negotiate contexts exist: modify `smb2_negotiate_request()` in `smb2pdu.c` -- **significant**, embedded in a ~500-line function.
8. Update `ksmbd_max_protocol()` and `ksmbd_lookup_protocol_idx()` -- trivial.

**Estimated total: M effort**. The ops/values pattern handles it reasonably well. The pain point is negotiate handling and any new commands/contexts that require modifying the `smb2pdu.c` monolith.

- **Current state**: Ops table pattern works adequately for version addition.
- **Issue**: Negotiate handling and command dispatch are not extensible; they require monolith modification.
- **Proposal**: Introduce a protocol version registration API:
  ```c
  struct ksmbd_protocol_version {
      __u16 protocol_id;
      const char *version_string;
      struct smb_version_ops *ops;
      struct smb_version_values *default_values;
      struct smb_version_cmds *cmds;
      unsigned int max_cmds;
      int (*negotiate_context_handler)(struct ksmbd_work *work);
      struct list_head list;
  };
  int ksmbd_register_protocol_version(struct ksmbd_protocol_version *ver);
  void ksmbd_unregister_protocol_version(struct ksmbd_protocol_version *ver);
  ```
- **Impact**: New protocol versions can be added without modifying existing code.
- **Effort**: L
- **Risk**: Over-engineering for a protocol that changes infrequently; potential overhead in hot path.
- **Priority**: P2

### 3.2 Protocol Dispatch Extensibility

#### Command Dispatch

- **Current state**: Single static `smb2_0_server_cmds[NUMBER_OF_SMB2_COMMANDS]` array. All SMB2/3 versions share it. `NUMBER_OF_SMB2_COMMANDS` is 20 (0x0013 + 1). Each entry is simply `{ .proc = handler_fn }`.
- **Issue**: No per-version command overrides. No way to add vendor-specific or experimental commands. No pre/post hooks for commands.
- **Proposal**: Three-tiered dispatch:
  1. Keep the static table as the default.
  2. Add per-connection command override array: `conn->cmd_overrides[NUMBER_OF_SMB2_COMMANDS]`.
  3. Add a pre/post hook registration mechanism for cross-cutting concerns (audit, tracing, extensions).
- **Impact**: Enables per-version command differences and extension commands.
- **Effort**: M
- **Risk**: Performance impact from additional indirection; complexity in hook ordering.
- **Priority**: P2

### 3.3 Create Context Handling

- **Current state**: Create contexts are processed in a long sequential block within `smb2_open()` (the CREATE handler, ~1000 lines). Each context is found via `smb2_find_context_vals()` with a 4-byte or 16-byte tag string, then processed inline. The AAPL/Fruit context was recently added at the end of this chain.
- **Issue**: Adding a new create context requires:
  1. Defining the tag string constant in `smb2pdu.h`.
  2. Adding a `smb2_find_context_vals()` call in `smb2_open()`.
  3. Adding inline processing logic in `smb2_open()`.
  4. Adding response context generation.
  This is entirely procedural and non-modular. The Fruit extension (`smb2fruit.c`) partially demonstrates better factoring by extracting logic into separate functions, but the dispatch point is still in `smb2_open()`.
- **Proposal**: Create context handler registration:
  ```c
  struct ksmbd_create_context_handler {
      const char *tag;              /* e.g., "AAPL", "ExtA" */
      size_t tag_len;               /* 4 or 16 */
      int (*on_create_request)(struct ksmbd_work *work,
                               struct ksmbd_file *fp,
                               const struct create_context *ctx,
                               struct create_context **rsp_ctx);
      int (*on_create_response)(struct ksmbd_work *work,
                                struct ksmbd_file *fp,
                                struct create_context **rsp_ctx);
      struct list_head list;
  };
  int ksmbd_register_create_context(struct ksmbd_create_context_handler *h);
  void ksmbd_unregister_create_context(struct ksmbd_create_context_handler *h);
  ```
  The `smb2_open()` function would iterate registered handlers for each context found in the request.
- **Impact**: New create contexts (DFS, witness, custom vendor contexts) can be added as separate modules.
- **Effort**: L
- **Risk**: Ordering dependencies between context handlers; error propagation complexity.
- **Priority**: P1

### 3.4 IOCTL/FSCTL Dispatch

- **Current state**: The `smb2_ioctl()` handler in `smb2pdu.c` contains a ~300-line `switch (cnt_code)` block handling 14 distinct FSCTLs. Each case is inline code or calls a helper function (e.g., `fsctl_copychunk()`, `fsctl_query_iface_info_ioctl()`).
- **Issue**: Adding a new FSCTL requires modifying `smb2_ioctl()` in `smb2pdu.c`. The switch statement will only grow. Some FSCTLs are stubbed out (DFS returns `-EOPNOTSUPP`), but there is no mechanism to register handlers from outside.
- **Proposal**: FSCTL handler registration table:
  ```c
  struct ksmbd_fsctl_handler {
      __le32 ctl_code;
      int (*handler)(struct ksmbd_work *work,
                     u64 id, void *buffer,
                     unsigned int in_buf_len,
                     unsigned int out_buf_len,
                     struct smb2_ioctl_rsp *rsp,
                     unsigned int *nbytes);
      struct hlist_node node;
  };
  int ksmbd_register_fsctl(struct ksmbd_fsctl_handler *h);
  void ksmbd_unregister_fsctl(struct ksmbd_fsctl_handler *h);
  ```
  The `smb2_ioctl()` function would first look up the handler in a hash table before falling through to the default switch.
- **Impact**: DFS, server-side copy, and vendor-specific FSCTLs can be separate modules.
- **Effort**: M
- **Risk**: Low -- the existing code already uses a dispatch pattern; this just makes it runtime-extensible.
- **Priority**: P1

### 3.5 Information Level Handlers (QUERY_INFO / SET_INFO)

- **Current state**: `smb2_get_info_file()` handles 15 file info classes via switch-case. `smb2_get_info_filesystem()` handles 10 filesystem info classes. `smb2_set_info_file()` handles 5 cases. `smb2_get_info_sec()` handles security descriptors. The top-level `smb2_query_info()` dispatches on `SMB2_O_INFO_FILE`, `SMB2_O_INFO_FILESYSTEM`, `SMB2_O_INFO_SECURITY`.
- **Issue**: Same problem as FSCTL -- all info levels are hardcoded switch-case. Adding `FILE_QUOTA_INFORMATION` or `FS_SECTOR_SIZE_INFORMATION` requires modifying the monolith.
- **Proposal**: Info-level handler table:
  ```c
  struct ksmbd_info_handler {
      u8 info_type;          /* SMB2_O_INFO_FILE, etc. */
      u8 info_class;         /* FILE_BASIC_INFORMATION, etc. */
      int (*get_handler)(struct ksmbd_work *work, void *rsp, ...);
      int (*set_handler)(struct ksmbd_work *work, void *buf, ...);
      struct hlist_node node;
  };
  ```
- **Impact**: New information levels can be added without touching `smb2pdu.c`.
- **Effort**: M
- **Risk**: Must handle buffer sizing carefully; info levels have varying output sizes.
- **Priority**: P2

---

## 4. Coupling Analysis

### 4.1 Impact of Changing `struct ksmbd_conn`

**Current structure** (from `connection.h`): ~45 fields including protocol state, transport pointers, session management, credit tracking, locking primitives, signing keys, preauth state, and fruit extension state.

**Files that directly access `ksmbd_conn` members:**
- `smb2pdu.c` -- extensively (dialect, vals, ops, ClientGUID, signing_algorithm, preauth_info, sessions, etc.)
- `connection.c` -- allocation, lifecycle, session lookup
- `smb_common.c` -- ops dispatch, protocol negotiation
- `server.c` -- connection state checking
- `auth.c` -- signing keys, crypto operations
- `oplock.c` -- conn pointer in oplock_info
- `vfs_cache.c` -- session lookup through conn
- `transport_tcp.c` -- transport embedding
- `transport_ipc.c` -- peer address
- `smb2fruit.c` -- fruit_state pointer
- `mgmt/user_session.c` -- session registration/deregistration

**Impact assessment**: Changing `ksmbd_conn` would require modifications to **at minimum 11 source files**. The struct is a "god object" that concentrates too many responsibilities.

- **Current state**: `ksmbd_conn` is the central nervous system of ksmbd; every subsystem touches it.
- **Issue**: No encapsulation. Fields are accessed directly rather than through accessor functions. Adding a field to support a new feature (e.g., compression state, QUIC transport state) adds to the already large struct and risks ABI breakage.
- **Proposal**: Decompose `ksmbd_conn` into composed sub-structs:
  ```c
  struct ksmbd_conn {
      struct ksmbd_conn_transport transport_state;
      struct ksmbd_conn_protocol proto_state;
      struct ksmbd_conn_security sec_state;
      struct ksmbd_conn_credits credit_state;
      struct ksmbd_conn_sessions session_state;
      void *extension_data;  /* for Fruit, etc. */
  };
  ```
  Provide accessor macros/functions. Each sub-struct is owned by its respective subsystem.
- **Impact**: Enables independent evolution of subsystem state without touching other subsystems.
- **Effort**: XL
- **Risk**: Massive refactoring; potential cache-line optimization disruption; compile-time regression risk.
- **Priority**: P2

### 4.2 Impact of Changing `struct ksmbd_work`

**Current structure** (from `ksmbd_work.h`): ~30 fields including request/response buffers, connection pointer, session pointer, tree connect pointer, compound request state, async state, I/O vectors, and credential overrides.

**Files that directly access `ksmbd_work` members:**
- `smb2pdu.c` -- extensively (all buffer access, session, tcon, compound state)
- `server.c` -- request processing pipeline
- `ksmbd_work.c` -- allocation and lifecycle
- `smb_common.c` -- buffer access, credential overrides
- `connection.c` -- request queuing/dequeuing
- `oplock.c` -- async request handling
- `auth.c` -- signing context
- `vfs.c` -- credential context

**Impact assessment**: Changing `ksmbd_work` would affect **at minimum 8 files**. It is the second most coupled struct after `ksmbd_conn`.

- **Current state**: `ksmbd_work` carries the entire request context through the processing pipeline.
- **Issue**: The struct conflates request buffering, protocol state, session context, and I/O management. The `saved_cred` field for fsuid override is a particularly concerning coupling point between protocol handling and VFS operations.
- **Proposal**: Use a layered context model:
  ```c
  struct ksmbd_work {
      struct ksmbd_request_ctx req;   /* buffers, compound state */
      struct ksmbd_auth_ctx auth;     /* session, credentials */
      struct ksmbd_io_ctx io;         /* iov, response state */
      void *cmd_private;              /* per-command private data */
  };
  ```
- **Impact**: Cleaner separation of concerns in the request pipeline.
- **Effort**: L
- **Risk**: Performance impact from pointer chasing; significant code churn.
- **Priority**: P3

### 4.3 Impact of Changing Session Management

**Current session architecture**:
- `struct ksmbd_session` in `mgmt/user_session.h` -- ~25 fields
- Global hash table `sessions_table` in `mgmt/user_session.c`
- Per-connection session xarray in `ksmbd_conn.sessions`
- Session lookup functions: `ksmbd_session_lookup()`, `ksmbd_session_lookup_all()`, `ksmbd_session_lookup_slowpath()`

**Files that access session internals:**
- `smb2pdu.c` -- session setup, logoff, session key access, encryption keys
- `auth.c` -- session key generation and storage
- `server.c` -- session deregistration on connection close
- `oplock.c` -- session pointer in oplock_info
- `mgmt/user_session.c` -- session lifecycle
- `mgmt/tree_connect.c` -- tree connection per session

**Impact assessment**: Changing session management would affect **7+ files**. The session struct directly exposes cryptographic keys (`smb3encryptionkey`, `smb3decryptionkey`, `smb3signingkey`) which are accessed from `auth.c` and `smb2pdu.c`.

- **Current state**: Sessions are tightly coupled to both the connection layer and the authentication layer.
- **Issue**: No session abstraction interface. Auth code directly reads/writes session keys. The `ksmbd_session` struct is exposed to all consumers.
- **Proposal**: Introduce session accessor API:
  ```c
  int ksmbd_session_get_signing_key(struct ksmbd_session *sess, u8 *key, size_t *len);
  int ksmbd_session_set_signing_key(struct ksmbd_session *sess, const u8 *key, size_t len);
  ```
- **Impact**: Allows session key storage to be changed (e.g., moved to kernel keyring) without affecting consumers.
- **Effort**: M
- **Risk**: Low -- accessor overhead is negligible for non-hot-path operations.
- **Priority**: P2

### 4.4 Impact of Replacing the VFS Backend

**Current VFS integration points:**
- `vfs.c` -- 40+ functions calling Linux VFS directly
- `vfs_cache.c` -- file handle cache using `struct file *`
- `smb2pdu.c` -- direct `kern_path()`, `vfs_statfs()` calls bypassing `vfs.c`
- `smbacl.c` -- POSIX ACL manipulation via Linux VFS
- `ndr.c` -- xattr encoding for NTACL
- `compat.c` -- version-specific VFS shims

**Impact assessment**: Replacing the VFS backend would require changes to **at least 6 files**, with `smb2pdu.c` being the most problematic due to direct VFS calls.

- **Current state**: No VFS abstraction interface exists. The code calls Linux VFS APIs directly.
- **Issue**: Cannot substitute a different backend (e.g., for testing, or for a specialized filesystem). Cannot run ksmbd on top of a non-Linux VFS.
- **Proposal**: Define `struct ksmbd_vfs_ops`:
  ```c
  struct ksmbd_vfs_ops {
      int (*create)(struct ksmbd_vfs_ctx *ctx, const char *path, umode_t mode, ...);
      int (*read)(struct ksmbd_vfs_ctx *ctx, struct ksmbd_file *fp, ...);
      int (*write)(struct ksmbd_vfs_ctx *ctx, struct ksmbd_file *fp, ...);
      int (*stat)(struct ksmbd_vfs_ctx *ctx, const char *path, struct kstat *stat);
      int (*getxattr)(struct ksmbd_vfs_ctx *ctx, ...);
      int (*setxattr)(struct ksmbd_vfs_ctx *ctx, ...);
      /* ... ~30 more operations */
  };
  ```
- **Impact**: Enables mock VFS for testing; enables non-Linux backends; enables storage tiering.
- **Effort**: XL
- **Risk**: Significant performance overhead from indirection; enormous refactoring scope.
- **Priority**: P3

### 4.5 Hard-Coded Constants vs. Configurable Values

| Constant | Location | Current Value | Should Be Configurable? |
|---|---|---|---|
| `SMB2_MAX_CREDITS` | `smb_common.h` | 8192 | Yes -- already partially configurable via netlink |
| `NUMBER_OF_SMB2_COMMANDS` | `smb2pdu.h` | 20 | No -- protocol defined |
| `ksmbd_server_side_copy_max_chunk_count()` | `smb_common.c` | 256 | Yes -- should be runtime configurable |
| `ksmbd_server_side_copy_max_chunk_size()` | `smb_common.c` | 2GB-1 | Yes -- should be runtime configurable |
| `KSMBD_IPC_MAX_PAYLOAD` | `transport_ipc.h` | 4096 | Maybe -- limits RPC payload |
| `IPC_WAIT_TIMEOUT` | `transport_ipc.c` | 2*HZ | Yes -- hardcoded, should come from config |
| `MAX_CIFS_SMALL_BUFFER_SIZE` | `smb_common.h` | 448 | No -- protocol constraint |
| `SMB3_MAX_IOSIZE` | `smb_common.h` | 8MB | Partially -- configurable via netlink |
| `CONN_HASH_BITS` | `connection.h` | 12 | Maybe -- affects scalability |
| `SESSION_HASH_BITS` | `user_session.c` | 12 | Maybe -- affects scalability |
| `SHARE_HASH_BITS` | `share_config.c` | 12 | No -- unlikely to have 4K+ shares |
| `SMB_ECHO_INTERVAL` | `server.h` | 60s | Yes -- should be configurable |

- **Current state**: Mix of `#define` constants and function-returned values. Some are configurable via netlink startup request, others are not.
- **Issue**: No unified configuration registry. Changing a value requires recompilation.
- **Proposal**: Create a `struct ksmbd_server_tunables` with all runtime-tunable values, populated from the netlink startup request with sane defaults.
- **Impact**: Administrators can tune without recompiling.
- **Effort**: M
- **Risk**: Invalid configuration values could cause instability; needs validation.
- **Priority**: P1

---

## 5. Modular Design Opportunities

### 5.1 Fruit/AAPL Extension

- **Current state**: Already partially modular with `CONFIG_KSMBD_FRUIT` compile-time toggle. `smb2fruit.h` provides a full inline-stub API when disabled. `smb2fruit.c` is compiled only when enabled. However, the connection struct has a `fruit_state` pointer, and both `connection.c` and `smb2pdu.c` have `#ifdef CONFIG_KSMBD_FRUIT` blocks.
- **Issue**: Not a true loadable module. The compile-time toggle is in the `Makefile` as `CONFIG_KSMBD_FRUIT ?= n`, not in `Kconfig`. The fruit state is embedded in the connection cleanup path, creating a compile-time dependency even at the framework level.
- **Proposal**: Make Fruit a runtime-registerable extension:
  1. Add `CONFIG_KSMBD_FRUIT` to `Kconfig` (currently missing).
  2. Use the create context handler registration (Section 3.3) for AAPL context.
  3. Use `conn->extension_data` void pointer with a tagged-union or linked list for per-connection extension state.
  4. Register/unregister via `fruit_init_module()`/`fruit_cleanup_module()`.
- **Impact**: Fruit can be a separate `.ko` module loaded on demand.
- **Effort**: M
- **Risk**: Low -- the stubs already exist; just needs runtime registration plumbing.
- **Priority**: P1

### 5.2 RDMA Transport

- **Current state**: `transport_rdma.c` is compiled conditionally via `CONFIG_SMB_SERVER_SMBDIRECT`. The header `transport_rdma.h` provides inline stubs when disabled. The transport is initialized in `connection.c:ksmbd_conn_transport_init()`.
- **Issue**: While the transport ops abstraction is clean, the RDMA-specific `rdma_read`/`rdma_write` ops in the base transport table leak the RDMA abstraction. The RDMA code itself is well-isolated.
- **Proposal**:
  1. Move `rdma_read`/`rdma_write` to a secondary ops table or use the base `read`/`writev` with capability flags.
  2. Make RDMA a separate loadable module that registers its transport factory.
  3. Define a transport registration API:
     ```c
     struct ksmbd_transport_factory {
         const char *name;
         int (*create_listener)(struct ksmbd_transport_factory *f, ...);
         void (*destroy)(struct ksmbd_transport_factory *f);
         struct list_head list;
     };
     int ksmbd_register_transport(struct ksmbd_transport_factory *f);
     void ksmbd_unregister_transport(struct ksmbd_transport_factory *f);
     ```
- **Impact**: RDMA can be loaded independently; future transports (QUIC) plug in.
- **Effort**: M
- **Risk**: Transport initialization ordering; must ensure base transport is available.
- **Priority**: P2

### 5.3 SMB1 Support

- **Current state**: Gated with `CONFIG_SMB_INSECURE_SERVER`. Separate files: `smb1pdu.c`, `smb1ops.c`, `smb1misc.c`, `netmisc.c`. Extensive `#ifdef CONFIG_SMB_INSECURE_SERVER` blocks in shared code (`connection.c`, `smb_common.c`, `oplock.c`, `auth.c`, `mgmt/user_session.h`).
- **Issue**: The `#ifdef` blocks are scattered across **at least 8 files**. The SMB1 code path is interleaved with SMB2/3 code in `smb_common.c` (negotiate handling), `connection.c` (write handling with different iov paths), and `oplock.c` (oplock level handling). This is the worst of both worlds -- not cleanly separated enough to be a module, but gated enough to be confusing.
- **Proposal**:
  1. Move ALL SMB1-specific branches from shared files into SMB1-specific files.
  2. Define `smb1_version_ops` registration (already partially exists) that plugs into the same framework as SMB2.
  3. The negotiate path in `smb_common.c` should dispatch to a registered "negotiate handler" rather than having inline SMB1 logic.
  4. Long-term: make SMB1 a separate `.ko` module.
- **Impact**: Cleaner codebase for the default (non-SMB1) build; reduced `#ifdef` pollution.
- **Effort**: L
- **Risk**: Behavioral changes in edge cases where SMB1 and SMB2 paths interact.
- **Priority**: P2

### 5.4 Kerberos Authentication

- **Current state**: Kerberos authentication is already delegated to userspace via the `ksmbd_ipc_spnego_authen_request()` netlink call. The kernel side handles ASN.1 SPNEGO token parsing (`asn1.c`) and forwards the Kerberos blob to `ksmbd.mountd`. The `auth.c` file handles NTLM locally and Kerberos via IPC.
- **Issue**: The SPNEGO/ASN.1 parsing in `asn1.c` is a security-sensitive component that could benefit from isolation. The auth mechanism selection is embedded in `smb2_sess_setup()` in `smb2pdu.c`. There is no pluggable authentication framework.
- **Proposal**: Authentication provider registration:
  ```c
  struct ksmbd_auth_provider {
      const char *name;
      unsigned int mech_type;   /* KSMBD_AUTH_NTLMSSP, KSMBD_AUTH_KRB5, etc. */
      int (*authenticate)(struct ksmbd_session *sess,
                          struct ksmbd_conn *conn,
                          void *sec_blob, size_t blob_len,
                          void **rsp_blob, size_t *rsp_len);
      int (*generate_session_key)(struct ksmbd_session *sess, ...);
      struct list_head list;
  };
  int ksmbd_register_auth_provider(struct ksmbd_auth_provider *p);
  ```
- **Impact**: New auth mechanisms (e.g., certificate-based, token-based) can be added as modules.
- **Effort**: L
- **Risk**: Security-critical path; must maintain atomicity of auth state transitions.
- **Priority**: P2

### 5.5 ACL/Permission Engine

- **Current state**: `smbacl.c` implements Windows-to-POSIX ACL translation. It directly uses Linux VFS POSIX ACL APIs and xattr interfaces for NTACL storage. `ndr.c` handles NDR encoding/decoding for ACL xattr storage.
- **Issue**: The ACL engine is tightly coupled to:
  1. The on-disk xattr format (Samba compatibility constraint).
  2. POSIX ACL semantics.
  3. The `ksmbd_share_config` for permission masking.
  There is no abstraction -- `smb2pdu.c` calls `smbacl.c` functions directly, and `smbacl.c` calls VFS functions directly.
- **Proposal**: Define a `struct ksmbd_acl_ops` interface:
  ```c
  struct ksmbd_acl_ops {
      int (*get_sd)(struct ksmbd_file *fp, struct smb_ntsd **sd, unsigned int *sd_len);
      int (*set_sd)(struct ksmbd_file *fp, struct smb_ntsd *sd, unsigned int sd_len, unsigned int dacl_flags);
      int (*check_access)(struct ksmbd_file *fp, __le32 desired_access);
  };
  ```
- **Impact**: Enables alternative ACL backends (e.g., NFSv4 ACLs, Richacls).
- **Effort**: M
- **Risk**: ACL semantics are complex; abstraction may not capture all edge cases.
- **Priority**: P3

### 5.6 Oplock/Lease Engine

- **Current state**: `oplock.c` is a 1700+ line file managing oplock/lease state with its own data structures (`oplock_info`, `lease`, `lease_table`), its own locking (`lease_list_lock`, `lb_lock`), and its own lifecycle management. It is already relatively self-contained.
- **Issue**: The oplock engine has direct dependencies on:
  1. `ksmbd_conn` -- for break notifications.
  2. `ksmbd_session` -- stored in `oplock_info`.
  3. SMB1 protocol specifics (`#ifdef CONFIG_SMB_INSECURE_SERVER` in alloc_opinfo).
  4. Direct send functions for break notifications.
- **Proposal**: The oplock engine is the closest to being a standalone module already. To complete the isolation:
  1. Define `struct ksmbd_oplock_ops` for the break notification callback.
  2. Remove direct `ksmbd_conn`/`ksmbd_session` references from `oplock_info`; use opaque identifiers.
  3. Move all oplock-related code (currently some in `smb2pdu.c`) into `oplock.c`.
- **Impact**: Oplock engine can be tested independently; potentially reused by other kernel file servers.
- **Effort**: M
- **Risk**: Timing-sensitive oplock break handling could be affected by additional indirection.
- **Priority**: P3

### 5.7 DFS/Referral Support

- **Current state**: DFS is explicitly not supported. The IOCTL handler returns `-EOPNOTSUPP` / `STATUS_FS_DRIVER_REQUIRED` for `FSCTL_DFS_GET_REFERRALS` and `FSCTL_DFS_GET_REFERRALS_EX`. There is no DFS-related code.
- **Issue**: DFS is an important enterprise feature. When implemented, it should be modular from the start.
- **Proposal**: Implement DFS as a loadable module:
  1. Register FSCTL handlers for referral requests.
  2. Define a referral provider interface for different DFS configurations.
  3. Add a negotiate context handler for DFS capability advertisement.
  4. Integrate with tree-connect for path redirection.
- **Impact**: Enterprise feature with zero overhead when not loaded.
- **Effort**: L (framework) + XL (full DFS implementation)
- **Risk**: DFS has complex interactions with path resolution and share configuration.
- **Priority**: P1 (framework), P2 (implementation)

### 5.8 RPC/DCERPC Server

- **Current state**: RPC is delegated to userspace via `ksmbd_rpc_*()` functions in `transport_ipc.c`. The kernel side acts as a pass-through, forwarding RPC pipe operations to `ksmbd.mountd` and returning responses.
- **Issue**: The IPC round-trip for every RPC call adds latency. Some frequently-called RPCs (e.g., `NetShareEnumAll`) could benefit from kernel-side caching or implementation.
- **Proposal**: Hybrid RPC model:
  1. Define `struct ksmbd_rpc_handler` registration for kernel-side RPC implementations.
  2. Fall back to userspace IPC for unregistered RPC interfaces.
  3. Start with caching: kernel caches share enum results from userspace.
- **Impact**: Reduced latency for common RPC operations; reduced IPC load.
- **Effort**: L (caching) + XL (kernel-side RPC)
- **Risk**: Consistency between kernel cache and userspace state; security of kernel RPC implementations.
- **Priority**: P3

---

## 6. ABI/API Design Principles

### 6.1 Proposed Module Boundary APIs

For each proposed module boundary, the following principles should apply:

#### 6.1.1 Header Organization

```
include/ksmbd/
    ksmbd_api.h           -- Stable public API (version-stamped)
    ksmbd_transport.h     -- Transport registration API
    ksmbd_protocol.h      -- Protocol version registration
    ksmbd_auth.h          -- Authentication provider API
    ksmbd_extension.h     -- Extension (create context, FSCTL) registration
    ksmbd_vfs.h           -- VFS operations interface

internal/
    ksmbd_conn_internal.h -- Internal connection state (not for modules)
    ksmbd_work_internal.h -- Internal work queue state
    ksmbd_session_internal.h -- Internal session management
```

**Principle**: Public headers define stable interfaces with opaque types. Internal headers contain implementation details.

#### 6.1.2 What Goes in the API Header (Stable Interfaces)

```c
/* ksmbd_extension.h - Stable extension API */

#define KSMBD_EXTENSION_API_VERSION 1

/* Opaque types -- modules cannot dereference these */
struct ksmbd_work;
struct ksmbd_file;
struct ksmbd_conn;
struct ksmbd_session;

/* Extension context -- modules access request data through this */
struct ksmbd_ext_ctx {
    void *request_data;
    size_t request_len;
    void *response_buf;
    size_t response_buf_len;
    size_t *response_len;
};

/* FSCTL handler registration */
struct ksmbd_fsctl_handler {
    __le32 ctl_code;
    int (*handler)(struct ksmbd_ext_ctx *ctx);
    struct module *owner;
    struct list_head list;
};

int ksmbd_register_fsctl_handler(struct ksmbd_fsctl_handler *h);
void ksmbd_unregister_fsctl_handler(struct ksmbd_fsctl_handler *h);
```

#### 6.1.3 What is Internal Implementation Detail

```c
/* ksmbd_conn_internal.h - NOT for module use */

struct ksmbd_conn {
    /* Full struct definition with all fields */
    struct ksmbd_transport *transport;
    struct smb_version_ops *ops;
    /* ... etc. */
};
```

#### 6.1.4 Versioning Strategy

```c
/* In ksmbd_api.h */
#define KSMBD_API_VERSION_MAJOR 1
#define KSMBD_API_VERSION_MINOR 0

struct ksmbd_module_info {
    unsigned int api_version_major;
    unsigned int api_version_minor;
    const char *name;
    const char *description;
};

/* Modules declare their API version requirement */
#define KSMBD_MODULE_INFO(mod_name, desc) \
    static struct ksmbd_module_info __ksmbd_mod_info = { \
        .api_version_major = KSMBD_API_VERSION_MAJOR, \
        .api_version_minor = KSMBD_API_VERSION_MINOR, \
        .name = mod_name, \
        .description = desc, \
    }

/* Registration validates version compatibility */
```

#### 6.1.5 Module Registration/Unregistration

```c
/* Registration pattern -- follows Linux kernel conventions */
static int __init ksmbd_dfs_init(void)
{
    int ret;

    ret = ksmbd_register_fsctl_handler(&dfs_get_referrals_handler);
    if (ret)
        return ret;

    ret = ksmbd_register_fsctl_handler(&dfs_get_referrals_ex_handler);
    if (ret) {
        ksmbd_unregister_fsctl_handler(&dfs_get_referrals_handler);
        return ret;
    }

    return 0;
}

static void __exit ksmbd_dfs_exit(void)
{
    ksmbd_unregister_fsctl_handler(&dfs_get_referrals_handler);
    ksmbd_unregister_fsctl_handler(&dfs_get_referrals_ex_handler);
}

module_init(ksmbd_dfs_init);
module_exit(ksmbd_dfs_exit);
```

#### 6.1.6 Error Propagation Across Boundaries

```c
/* Errors propagate as standard kernel error codes */
/* Extension handlers return:
 *   0          -- success, framework sends response
 *   -EOPNOTSUPP -- not handled, try next handler
 *   -EINVAL    -- input validation failure
 *   -ENOMEM    -- allocation failure
 *   -EACCES    -- permission denied
 *   Other      -- mapped to STATUS_INTERNAL_ERROR
 */

/* The framework maps kernel errors to SMB status codes */
static __le32 ksmbd_ext_error_to_status(int err) {
    switch (err) {
    case 0: return STATUS_SUCCESS;
    case -EINVAL: return STATUS_INVALID_PARAMETER;
    case -EACCES: return STATUS_ACCESS_DENIED;
    case -ENOMEM: return STATUS_INSUFFICIENT_RESOURCES;
    case -EOPNOTSUPP: return STATUS_NOT_SUPPORTED;
    default: return STATUS_INTERNAL_ERROR;
    }
}
```

#### 6.1.7 Performance Across Module Boundaries

**Principles:**
1. **No double-copy**: Extension handlers receive direct pointers to request data; they write directly into the response buffer.
2. **No extra allocation**: The framework pre-allocates response buffers; extensions fill them in-place.
3. **Inline hot path**: The dispatch lookup (hash table or direct index) should be lock-free for the read path (RCU-protected).
4. **Module reference counting**: Use `try_module_get(handler->owner)` before invoking; `module_put()` after. This prevents module unload during operation.

```c
/* Hot-path dispatch using RCU-protected hash lookup */
int ksmbd_dispatch_fsctl(struct ksmbd_work *work, __le32 ctl_code, ...)
{
    struct ksmbd_fsctl_handler *h;
    int ret = -EOPNOTSUPP;

    rcu_read_lock();
    h = ksmbd_fsctl_lookup(ctl_code);  /* RCU-safe hash lookup */
    if (h && try_module_get(h->owner)) {
        rcu_read_unlock();
        ret = h->handler(&ext_ctx);
        module_put(h->owner);
    } else {
        rcu_read_unlock();
    }

    return ret;
}
```

---

## 7. Configuration Architecture

### 7.1 Current Configuration Model

The current configuration uses three distinct mechanisms:

1. **Compile-time (`Kconfig` + `Makefile`):**
   - `CONFIG_SMB_SERVER` -- module enable
   - `CONFIG_SMB_INSECURE_SERVER` -- SMB1 support
   - `CONFIG_SMB_SERVER_SMBDIRECT` -- RDMA support
   - `CONFIG_KSMBD_FRUIT` -- Apple Fruit extensions (Makefile only, NOT in Kconfig)
   - `CONFIG_SMB_SERVER_CHECK_CAP_NET_ADMIN` -- capability check

2. **Startup-time (netlink `ksmbd_startup_request`):**
   - Global flags (leases, encryption, multichannel, durable handles, fruit)
   - Protocol version range
   - Signing mode
   - Resource limits (max read/write/trans, max credits, max connections)
   - Network configuration (TCP port, bind interfaces)
   - Identity (netbios name, workgroup, server string)
   - Fruit model string

3. **Runtime (sysfs):**
   - Debug level toggling (`/sys/class/ksmbd-control/debug`)
   - Server kill (`/sys/class/ksmbd-control/kill_server`)
   - Stats viewing (`/sys/class/ksmbd-control/stats`)

### 7.2 Configuration Issues

| Issue | Description | Severity |
|---|---|---|
| **No Kconfig for Fruit** | `CONFIG_KSMBD_FRUIT` is in the Makefile as `?= n`, not in `Kconfig`. This means `menuconfig` cannot toggle it, and kernel build systems do not know about it. | HIGH |
| **Mixed configuration sources** | Some tunables are compile-time only (hash table sizes), some are startup-time only (max sizes), and some are neither (copy chunk limits are hardcoded function return values). No unified model. | MEDIUM |
| **No runtime reconfiguration** | Once started, server parameters cannot be changed without a full reset. The netlink interface only handles startup configuration. | MEDIUM |
| **Feature flags scattered** | `KSMBD_GLOBAL_FLAG_*` constants are in `ksmbd_netlink.h`. `KSMBD_SHARE_FLAG_*` constants are also there. These are ABI-fixed. Adding new flags requires careful ABI management. | MEDIUM |
| **No validation framework** | `ksmbd_startup_request` values are used directly. There is some clamping (e.g., `clamp_val` for I/O sizes) but no comprehensive validation. | LOW |

### 7.3 Proposed Unified Configuration Framework

```c
/* ksmbd_config.h */

enum ksmbd_config_param {
    KSMBD_CFG_MIN_PROTOCOL,
    KSMBD_CFG_MAX_PROTOCOL,
    KSMBD_CFG_MAX_READ_SIZE,
    KSMBD_CFG_MAX_WRITE_SIZE,
    KSMBD_CFG_MAX_TRANS_SIZE,
    KSMBD_CFG_MAX_CREDITS,
    KSMBD_CFG_MAX_CONNECTIONS,
    KSMBD_CFG_MAX_CONNECTIONS_PER_IP,
    KSMBD_CFG_DEADTIME,
    KSMBD_CFG_COPY_CHUNK_MAX_COUNT,
    KSMBD_CFG_COPY_CHUNK_MAX_SIZE,
    KSMBD_CFG_SIGNING_REQUIRED,
    KSMBD_CFG_DEBUG_LEVEL,
    /* ... */
    __KSMBD_CFG_MAX,
};

struct ksmbd_config_param_desc {
    const char *name;
    enum { CFG_TYPE_U32, CFG_TYPE_U64, CFG_TYPE_STRING, CFG_TYPE_BOOL } type;
    union { u32 u32_val; u64 u64_val; const char *str_val; bool bool_val; } default_val;
    union { u32 u32_val; u64 u64_val; } min_val;
    union { u32 u32_val; u64 u64_val; } max_val;
    bool runtime_changeable;
};

int ksmbd_config_get_u32(enum ksmbd_config_param param, u32 *val);
int ksmbd_config_set_u32(enum ksmbd_config_param param, u32 val);
```

### 7.4 Feature Negotiation Model

- **Current state**: Features are either compile-time enabled/disabled or globally enabled via startup flags. Per-share features use share flags. There is no per-connection or per-session feature negotiation beyond what the SMB protocol itself provides.
- **Proposal**: Three-tier feature model:
  1. **Compile-time**: Feature code presence (Kconfig).
  2. **Global enable**: Feature can be activated (startup config).
  3. **Per-connection**: Feature negotiated per client (protocol negotiation + extension registration).
  Each tier gates the next. A feature must be compiled in AND globally enabled AND negotiated to be active for a connection.
- **Impact**: Administrators can selectively enable/disable features without recompilation.
- **Effort**: M
- **Risk**: Configuration state management complexity.
- **Priority**: P1

---

## 8. Testing Architecture

### 8.1 Current Test Infrastructure

- **Current state**: There is **no test infrastructure within the kernel module source**. There is a `test_framework/` directory referenced in some files but it is not part of the standard build.
- **Issue**: Zero unit tests. Testing relies entirely on external tools:
  - `smbtorture` (Samba test suite) for protocol compliance.
  - Manual testing with SMB clients.
  - `ksmbd.control` for runtime debug toggling.
  There are no automated regression tests, no fuzzing harnesses, and no CI/CD integration evident in the repository.

### 8.2 Unit Testing Framework

- **Proposal**: Adopt the kernel's `KUnit` framework for unit testing.
  ```c
  /* test/ksmbd_test_oplock.c */
  #include <kunit/test.h>

  static void test_oplock_alloc(struct kunit *test)
  {
      struct oplock_info *opi;
      /* ... setup ... */
      KUNIT_ASSERT_NOT_NULL(test, opi);
      KUNIT_EXPECT_EQ(test, opi->level, SMB2_OPLOCK_LEVEL_NONE);
  }

  static struct kunit_case ksmbd_oplock_test_cases[] = {
      KUNIT_CASE(test_oplock_alloc),
      {}
  };

  static struct kunit_suite ksmbd_oplock_test_suite = {
      .name = "ksmbd-oplock",
      .test_cases = ksmbd_oplock_test_cases,
  };
  kunit_test_suite(ksmbd_oplock_test_suite);
  ```

**Testable units that COULD have KUnit tests today:**

| Component | Test Type | Effort | Priority |
|---|---|---|---|
| NDR encode/decode (`ndr.c`) | Pure function testing | S | P0 |
| ACL translation (`smbacl.c`) | Pure function testing | S | P0 |
| Short name generation (`smb_common.c`) | Pure function testing | S | P1 |
| Credit management | State machine testing | M | P1 |
| Oplock state machine | State machine testing | M | P1 |
| Session lifecycle | Lifecycle testing | M | P2 |
| Shared mode checking | Logic testing | S | P1 |
| Misc utilities (`misc.c`) | Pure function testing | S | P0 |
| Crypto context pool | Pool management testing | M | P2 |

- **Impact**: Catches regressions early; enables confident refactoring.
- **Effort**: M (framework) + ongoing per test
- **Risk**: KUnit tests run in kernel context; must be careful with memory and locking.
- **Priority**: P0

### 8.3 Integration Testing

- **Proposal**: Create a test harness script that:
  1. Builds ksmbd as a module.
  2. Loads it with a test configuration.
  3. Runs `smbtorture` test suites against it.
  4. Validates results and generates a report.
  5. Supports specific test selection (e.g., `smb2.create`, `smb2.ioctl`).

```bash
#!/bin/bash
# tests/run_integration.sh
KSMBD_MODULE=./ksmbd.ko
SMBTORTURE=smbtorture
TEST_SHARE=//localhost/test

insmod $KSMBD_MODULE
# Start ksmbd.mountd with test config
ksmbd.mountd -c tests/smb.conf.test

$SMBTORTURE $TEST_SHARE -U testuser%password \
    smb2.create smb2.read smb2.write smb2.ioctl \
    smb2.oplock smb2.lease smb2.lock

rmmod ksmbd
```

- **Impact**: Automated regression detection.
- **Effort**: M
- **Risk**: Requires test environment setup; flaky on different kernel versions.
- **Priority**: P1

### 8.4 Fuzzing Harness

- **Proposal**: Implement fuzzing targets for security-critical parsing code:

| Target | Input | Coverage |
|---|---|---|
| SMB2 header parsing | Random SMB2 headers | `ksmbd_smb2_check_message()` |
| SPNEGO/ASN.1 parsing | Random ASN.1 blobs | `ksmbd_decode_negTokenInit()`, `ksmbd_decode_negTokenTarg()` |
| Create context parsing | Random context chains | `smb2_find_context_vals()` |
| NDR decode | Random NDR blobs | `ndr_decode_dos_attr()`, `ndr_decode_v4_ntacl()` |
| Path parsing | Random unicode paths | `convert_to_unix_name()`, `ksmbd_validate_filename()` |
| Negotiate request | Random negotiate PDUs | `ksmbd_negotiate_smb_dialect()` |

Tools: `syzkaller` (kernel fuzzer), custom `kcov`-guided fuzzers.

- **Impact**: Discovers memory safety bugs before they become CVEs.
- **Effort**: L per target
- **Risk**: Fuzzing can find issues that are hard to reproduce/fix.
- **Priority**: P0

### 8.5 CI/CD Integration

- **Proposal**: GitHub Actions workflow:
  ```yaml
  on: [push, pull_request]
  jobs:
    build:
      matrix:
        kernel: [6.1, 6.6, 6.8, 6.12]
      steps:
        - Build module against each kernel version
        - Run KUnit tests
        - Run sparse/smatch static analysis
        - Run coccinelle semantic patches
    integration:
      needs: build
      steps:
        - Boot test kernel in QEMU
        - Load module
        - Run smbtorture subset
  ```
- **Impact**: Prevents regressions; ensures multi-kernel compatibility.
- **Effort**: L
- **Risk**: CI infrastructure maintenance; flaky tests.
- **Priority**: P1

---

## 9. Kernel Integration Quality

### 9.1 Comparison with Other Kernel File Servers

| Feature | ksmbd | nfsd | ceph | orangefs |
|---|---|---|---|---|
| Ops table dispatch | Yes (`smb_version_ops`) | Yes (`nfsd_dispatch`) | Yes | Yes |
| Transport abstraction | Good (ops table) | Good (svc_xprt) | Good | Good |
| VFS abstraction | Weak (direct VFS calls) | Moderate (`nfsd_file`) | Strong (`ceph_mds_ops`) | Strong |
| Sysfs/debugfs | Basic sysfs only | debugfs + procfs | debugfs + sysfs | sysfs + debugfs |
| Loadable sub-modules | None | NFSv4.1 callbacks | MDS client | N/A |
| KUnit tests | None | Some | Some | None |
| Netlink config | Good | Some | N/A | N/A |
| Workqueue usage | `system_wq` + custom | `nfsd_wq` | Custom | Custom |
| Cache management | Basic (`vfs_cache.c`) | `nfsd_file_cache` | Complex | Simple |

**Key gaps vs. nfsd:**
1. nfsd has a proper `nfsd_dispatch` mechanism with per-version dispatch tables that can be loaded/unloaded.
2. nfsd uses `svc_process()` as a single entry point with clean layering.
3. nfsd has debugfs for detailed runtime introspection.
4. nfsd separates protocol encoding (XDR) from handler logic -- ksmbd mixes them in `smb2pdu.c`.

### 9.2 Use of Kernel Frameworks

| Framework | Current Usage | Quality | Improvement Opportunity |
|---|---|---|---|
| **Workqueue** | Uses `system_wq` for connection handling; `system_long_wq` for server control | Adequate | Consider dedicated workqueue with tunable parameters for SMB request processing |
| **Netlink** | Generic netlink for kernel-userspace IPC | Good | Well-structured; could add more message types for runtime config |
| **Crypto** | Proper use of kernel crypto API via `crypto_ctx.c` pool | Good | Pool is well-designed; consider using `CRYPTO_ALG_ASYNC` for better performance on hardware |
| **VFS** | Direct VFS API calls | Adequate | Should use `vfs_ioc_setflags_prepare()` and newer APIs where available |
| **XArray** | Used for sessions, channels, tree connects | Good | Proper use of modern kernel data structure |
| **IDA** | Used for ID allocation | Good | Standard kernel pattern |
| **RCU** | Limited use (lease list) | Weak | Many data structures that are read-heavy could benefit from RCU |
| **Ref counting** | Custom `atomic_t` refcounting | Adequate | Should use `refcount_t` instead of `atomic_t` for overflow protection |
| **Slab** | No dedicated slab caches | Weak | Hot-path objects (work, oplock_info) should use dedicated kmem_cache |

### 9.3 Opportunities to Use Newer Kernel Features

#### io_uring (Linux 5.1+)

- **Opportunity**: io_uring could replace the per-connection kthread model for I/O processing, enabling zero-copy receive and batched operations.
- **Assessment**: Premature. io_uring server-side support is still evolving. The current kthread model is simple and functional.
- **Priority**: P3

#### fs_context (Linux 5.1+)

- **Opportunity**: Not directly applicable since ksmbd does not mount filesystems. However, the `fs_context` pattern of structured configuration parsing could inspire the configuration framework.
- **Priority**: N/A

#### refcount_t (Linux 4.11+)

- **Opportunity**: Replace all `atomic_t` reference counting with `refcount_t` for saturation-based overflow protection.
- **Locations**: `ksmbd_conn.refcnt`, `ksmbd_session.refcnt`, `ksmbd_share_config.refcount`, `ksmbd_tree_connect.refcount`, `oplock_info.refcount`.
- **Effort**: S
- **Risk**: None -- drop-in replacement.
- **Priority**: P0

#### debugfs (Linux 2.6.x+)

- **Opportunity**: Add debugfs entries for detailed runtime introspection:
  - Per-connection state dump
  - Active session listing
  - Oplock/lease table dump
  - Credit balance monitoring
  - IPC message statistics
- **Effort**: M
- **Risk**: Information disclosure if not properly restricted.
- **Priority**: P1

#### kmem_cache (Slab allocator)

- **Opportunity**: Create dedicated slab caches for frequently allocated objects:
  ```c
  static struct kmem_cache *ksmbd_work_cache;
  static struct kmem_cache *ksmbd_oplock_cache;
  static struct kmem_cache *ksmbd_file_cache;
  ```
  The `ksmbd_work` pool already exists (`ksmbd_work_pool_init()`) but uses a mempool on top of `kmalloc`, not a dedicated slab.
- **Effort**: S
- **Risk**: Memory fragmentation in low-memory situations.
- **Priority**: P1

---

## 10. Consolidated Recommendations

### Priority P0 -- Critical (Do First)

| # | Recommendation | Effort | Section |
|---|---|---|---|
| P0-1 | Add `CONFIG_KSMBD_FRUIT` to `Kconfig` (currently Makefile-only) | S | 7.2 |
| P0-2 | Replace `atomic_t` ref counting with `refcount_t` throughout | S | 9.3 |
| P0-3 | Create KUnit test framework with initial tests for NDR, ACL, misc | M | 8.2 |
| P0-4 | Create fuzzing harnesses for SMB2 header and ASN.1 parsing | L | 8.4 |

### Priority P1 -- High (Do Soon)

| # | Recommendation | Effort | Section |
|---|---|---|---|
| P1-1 | Implement FSCTL handler registration table | M | 3.4 |
| P1-2 | Implement create context handler registration | L | 3.3 |
| P1-3 | Break circular dependencies with layered header architecture | L | 2.2 |
| P1-4 | Create unified configuration framework with validation | M | 7.3 |
| P1-5 | Add debugfs interface for runtime introspection | M | 9.3 |
| P1-6 | Create dedicated slab caches for hot-path objects | S | 9.3 |
| P1-7 | Set up CI/CD pipeline with multi-kernel build and integration tests | L | 8.5 |
| P1-8 | Implement runtime-tunable server parameters | M | 4.5 |
| P1-9 | Create DFS extension framework (even before implementing DFS) | L | 5.7 |

### Priority P2 -- Medium (Planned Improvements)

| # | Recommendation | Effort | Section |
|---|---|---|---|
| P2-1 | Decompose `smb2pdu.c` into sub-files by command group | L | 2.1 |
| P2-2 | Protocol version registration API | L | 3.1 |
| P2-3 | Per-command dispatch overrides and hook mechanism | M | 3.2 |
| P2-4 | Info-level handler registration table | M | 3.5 |
| P2-5 | Make Fruit a runtime-loadable extension module | M | 5.1 |
| P2-6 | Clean up RDMA transport abstraction leakage | S | 5.2 |
| P2-7 | Clean SMB1 separation (remove `#ifdef` scatter) | L | 5.3 |
| P2-8 | Authentication provider registration API | L | 5.4 |
| P2-9 | Decompose `ksmbd_conn` into sub-structs | XL | 4.1 |
| P2-10 | Session accessor API for key management | M | 4.3 |
| P2-11 | Three-tier VFS abstraction layer | XL | 2.3 |
| P2-12 | Transport factory registration API | M | 5.2 |

### Priority P3 -- Low (Long-Term Architecture)

| # | Recommendation | Effort | Section |
|---|---|---|---|
| P3-1 | Full VFS backend abstraction (`ksmbd_vfs_ops`) | XL | 4.4 |
| P3-2 | Layered `ksmbd_work` context model | L | 4.2 |
| P3-3 | ACL operations interface | M | 5.5 |
| P3-4 | Oplock engine full isolation | M | 5.6 |
| P3-5 | Kernel-side RPC caching | L | 5.8 |
| P3-6 | io_uring integration investigation | L | 9.3 |

---

## Appendix A: Dependency Graph (Simplified)

```
                        +-----------+
                        |  server.c |
                        +-----+-----+
                              |
              +---------------+----------------+
              |               |                |
       +------+------+  +----+-----+  +-------+-------+
       | connection.c|  | smb_common|  | transport_ipc |
       +------+------+  +----+-----+  +-------+-------+
              |               |                |
              |       +-------+-------+        |
              |       |               |        |
         +----+----+  |  +---------+  |  +-----+-----+
         |smb2pdu.c|--+->| auth.c  |  +->|  mgmt/*   |
         +----+----+     +---------+     +-----------+
              |
    +---------+---------+---------+
    |         |         |         |
+---+---+ +--+--+ +----+---+ +---+----+
| vfs.c | |oplock| |smbacl.c| |smb2fruit|
+-------+ +-----+ +--------+ +---------+
```

## Appendix B: File Size Analysis (Monolith Indicators)

| File | Lines | Assessment |
|---|---|---|
| `smb2pdu.c` | ~10,000+ | CRITICAL -- must be decomposed |
| `vfs.c` | ~2,000+ | Large but manageable |
| `oplock.c` | ~1,700+ | Reasonable for complexity |
| `auth.c` | ~1,500+ | Reasonable |
| `connection.c` | ~580 | Good |
| `server.c` | ~670 | Good |
| `smb_common.c` | ~890 | Acceptable |
| `transport_tcp.c` | ~600 | Good |
| `transport_ipc.c` | ~700 | Good |
| `smb2fruit.c` | ~500+ | Good -- well-factored extension |
| `smbacl.c` | ~1,400+ | Large; contains both POSIX and NT ACL logic |
| `vfs_cache.c` | ~700+ | Good |

## Appendix C: `smb2pdu.c` Decomposition Proposal

The single most impactful refactoring would be to split `smb2pdu.c`:

| Proposed File | Contents | Estimated Lines |
|---|---|---|
| `smb2_negotiate.c` | `smb2_negotiate_request()`, `smb2_handle_negotiate()`, negotiate context processing | ~800 |
| `smb2_session.c` | `smb2_sess_setup()`, `smb2_session_logoff()`, binding, channel management | ~500 |
| `smb2_tree.c` | `smb2_tree_connect()`, `smb2_tree_disconnect()` | ~300 |
| `smb2_create.c` | `smb2_open()`, create context processing, durable handle | ~2000 |
| `smb2_read_write.c` | `smb2_read()`, `smb2_write()`, `smb2_flush()` | ~600 |
| `smb2_query_set.c` | `smb2_query_info()`, `smb2_set_info()`, all info handlers | ~2000 |
| `smb2_dir.c` | `smb2_query_dir()`, directory enumeration | ~800 |
| `smb2_ioctl.c` | `smb2_ioctl()`, all FSCTL handlers | ~800 |
| `smb2_lock.c` | `smb2_lock()`, byte-range locks | ~400 |
| `smb2_notify.c` | `smb2_notify()`, change notification | ~200 |
| `smb2_misc.c` | `smb2_echo()`, `smb2_cancel()`, utility functions | ~300 |
| `smb2_pdu_common.c` | Shared helpers (`smb2_set_err_rsp()`, buffer pinning, credit management) | ~500 |

**Total estimated effort: XL**
**Impact: Transformative for maintainability and extensibility**

---

*End of Extensibility and Architecture Review*
