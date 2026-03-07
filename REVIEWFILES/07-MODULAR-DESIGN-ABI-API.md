# KSMBD Modular Architecture Design: ABI/API Specification

**Document Version**: 1.0
**Date**: 2026-02-22
**Scope**: Complete modular decomposition of the ksmbd in-kernel SMB3 server

---

## Table of Contents

1. [Phase 1: Current Architecture Analysis](#phase-1-current-architecture-analysis)
2. [Phase 2: Modular Architecture Design](#phase-2-modular-architecture-design)
3. [Phase 3: API Design Details](#phase-3-api-design-details)
4. [Phase 4: ABI Stability Plan](#phase-4-abi-stability-plan)
5. [Phase 5: Migration Plan](#phase-5-migration-plan)

---

## Phase 1: Current Architecture Analysis

### 1.1 File Inventory and Line Counts

The ksmbd module currently compiles as a single `ksmbd.ko` from these source files:

| File | Role | Approx Lines |
|------|------|-------------|
| `server.c/h` | Module init/exit, global config, server state machine | ~500 |
| `connection.c/h` | Connection lifecycle, handler loop, conn state | ~600 |
| `smb2pdu.c/h` | All SMB2/3 command handlers (NEGOTIATE through NOTIFY) | ~10,000 |
| `smb2ops.c` | Protocol version ops/values tables, command dispatch tables | ~400 |
| `smb2misc.c` | SMB2 header validation | ~400 |
| `smb_common.c/h` | Multi-protocol negotiation, shared mode checks, fsid override | ~900 |
| `auth.c/h` | NTLM/NTLMv2/Kerberos auth, signing, encryption key derivation | ~1,500 |
| `vfs.c/h` | Linux VFS wrapper operations | ~2,500 |
| `vfs_cache.c/h` | File handle table, inode hash, durable handle management | ~1,800 |
| `oplock.c/h` | Oplock/lease grant, break, state machine | ~1,800 |
| `transport_tcp.c/h` | TCP socket accept, read, write, interface management | ~700 |
| `transport_ipc.c/h` | Netlink IPC to ksmbd.mountd userspace daemon | ~1,000 |
| `transport_rdma.c/h` | SMB Direct over RDMA (conditional on CONFIG_SMB_SERVER_SMBDIRECT) | ~1,800 |
| `smbacl.c/h` | Windows ACL / POSIX ACL translation, security descriptors | ~1,400 |
| `ndr.c/h` | NDR encoding/decoding for xattr-stored metadata | ~600 |
| `crypto_ctx.c/h` | Crypto context pool (hash, AEAD allocations) | ~300 |
| `asn1.c` | SPNEGO/ASN.1 parsing for Kerberos | ~200 |
| `unicode.c/h` | UTF-8/UTF-16 conversion, NLS handling | ~400 |
| `misc.c/h` | Utility functions | ~200 |
| `smb2fruit.c/h` | Apple AAPL create context extensions (conditional on CONFIG_KSMBD_FRUIT) | ~500 |
| `compat.c/h` | Kernel version compatibility shims | ~200 |
| `mgmt/user_config.c/h` | User account management | ~200 |
| `mgmt/share_config.c/h` | Share configuration management | ~300 |
| `mgmt/tree_connect.c/h` | Tree connection management | ~250 |
| `mgmt/user_session.c/h` | Session lifecycle management | ~700 |
| `mgmt/ksmbd_ida.c/h` | IDA-based ID allocation | ~100 |

**Total**: approximately 27,000 lines of kernel C code in one module.

### 1.2 Dependency Graph (Function Call Map)

```
server.c (module entry point)
  +-- ksmbd_server_init()
  |     +-- ksmbd_work_pool_init()           [ksmbd_work.c]
  |     +-- ksmbd_inode_hash_init()          [vfs_cache.c]
  |     +-- ksmbd_init_file_cache()          [vfs_cache.c]
  |     +-- ksmbd_ipc_init()                 [transport_ipc.c]
  |     +-- ksmbd_crypto_create()            [crypto_ctx.c]
  |     +-- ksmbd_init_global_file_table()   [vfs_cache.c]
  |     +-- fruit_init_module()              [smb2fruit.c] (conditional)
  |
  +-- ksmbd_server_exit()
        +-- ksmbd_tcp_destroy()              [transport_tcp.c]
        +-- ksmbd_rdma_destroy()             [transport_rdma.c]
        +-- ksmbd_ipc_release()              [transport_ipc.c]
        +-- ksmbd_workqueue_destroy()        [ksmbd_work.c]
        +-- ksmbd_crypto_destroy()           [crypto_ctx.c]
        +-- fruit_cleanup_module()           [smb2fruit.c] (conditional)

connection.c (per-connection handler)
  +-- ksmbd_conn_handler_loop()
  |     +-- ksmbd_smb_request()              [smb_common.c]  -- validate protocol
  |     +-- ksmbd_init_smb_server()          [smb_common.c]  -- init version ops
  |     +-- ksmbd_verify_smb_message()       [smb_common.c]  -- validate header
  |     +-- conn->ops->allocate_rsp_buf()    [smb2ops.c]     -- via ops table
  |     +-- conn->ops->check_user_session()  [smb2ops.c]
  |     +-- conn->ops->get_ksmbd_tcon()      [smb2pdu.c]
  |     +-- conn->cmds[cmd].proc()           [smb2pdu.c]     -- command dispatch
  |     +-- conn->ops->set_sign_rsp()        [smb2ops.c]
  |     +-- conn->ops->encrypt_resp()        [smb2ops.c]

smb2pdu.c (command handlers) -- calls into:
  +-- auth.c          (session setup, signing, encryption)
  +-- vfs.c           (all file operations)
  +-- vfs_cache.c     (file handle lookup, open/close)
  +-- oplock.c        (oplock/lease grant and break)
  +-- smbacl.c        (security descriptor operations)
  +-- transport_ipc.c (RPC forwarding to userspace)
  +-- smb2fruit.c     (AAPL create context, ReadDirAttr)
  +-- ndr.c           (DOS attribute encoding)
  +-- mgmt/*          (session, tree, share, user management)
```

### 1.3 Current `#ifdef CONFIG_*` Boundaries

Three compile-time feature gates currently exist:

#### `CONFIG_SMB_INSECURE_SERVER` (bool, in Kconfig)
- **Scope**: Enables SMB1/CIFS and SMB2.0 protocol support
- **Files affected**: `smb_common.c/h`, `connection.c`, `vfs.h`, `vfs_cache.h`, `oplock.h`, `ksmbd_work.h`, `mgmt/user_session.h`, `smb2ops.c`
- **Adds files**: `smb1pdu.c`, `smb1ops.c`, `smb1misc.c`, `netmisc.c`
- **Pattern**: Sprinkled `#ifdef` blocks throughout core structs (adds fields to `ksmbd_work`, `ksmbd_file`, `oplock_info`, `ksmbd_dir_info`)

#### `CONFIG_SMB_SERVER_SMBDIRECT` (bool, in Kconfig)
- **Scope**: RDMA transport for SMB Direct
- **Files affected**: `transport_rdma.h` (stubs when disabled), `smb2pdu.c` (RDMA key handling)
- **Adds files**: `transport_rdma.c`
- **Pattern**: Clean separation via `transport_rdma.h` static inline stubs. Well-factored.

#### `CONFIG_KSMBD_FRUIT` (defined via Makefile ccflags)
- **Scope**: Apple AAPL SMB extensions for macOS compatibility
- **Files affected**: `smb2fruit.c/h`, `oplock.h` (create_fruit_rsp_buf), `vfs.h` (copy_xattrs, resolve_fileid)
- **Adds files**: `smb2fruit.c`
- **Pattern**: Mix of `#ifdef` in headers with static inline stubs, plus calls from `smb2pdu.c`

### 1.4 Current Abstraction Layers

#### Transport Abstraction (`struct ksmbd_transport_ops`)
Defined implicitly in `connection.h`:
```c
struct ksmbd_transport_ops {
    int  (*read)(struct ksmbd_transport *t, char *buf,
                 unsigned int to_read, int max_retries);
    int  (*writev)(struct ksmbd_transport *t, struct kvec *iov,
                   int nvecs, int size, bool need_invalidate,
                   unsigned int remote_key);
    void (*disconnect)(struct ksmbd_transport *t);
    void (*free_transport)(struct ksmbd_transport *t);
};
```
**Assessment**: Good abstraction. TCP and RDMA both implement this interface. The ops pointer is stored in `ksmbd_transport` and invoked from `connection.c`. This is the cleanest existing separation.

#### Protocol Version Abstraction (`struct smb_version_ops`)
Defined in `smb_common.h`:
```c
struct smb_version_ops {
    u16  (*get_cmd_val)(struct ksmbd_work *);
    int  (*init_rsp_hdr)(struct ksmbd_work *);
    void (*set_rsp_status)(struct ksmbd_work *, __le32);
    int  (*allocate_rsp_buf)(struct ksmbd_work *);
    int  (*set_rsp_credits)(struct ksmbd_work *);
    int  (*check_user_session)(struct ksmbd_work *);
    int  (*get_ksmbd_tcon)(struct ksmbd_work *);
    bool (*is_sign_req)(struct ksmbd_work *, unsigned int);
    int  (*check_sign_req)(struct ksmbd_work *);
    void (*set_sign_rsp)(struct ksmbd_work *);
    int  (*generate_signingkey)(struct ksmbd_session *, struct ksmbd_conn *);
    int  (*generate_encryptionkey)(struct ksmbd_conn *, struct ksmbd_session *);
    bool (*is_transform_hdr)(void *buf);
    int  (*decrypt_req)(struct ksmbd_work *);
    int  (*encrypt_resp)(struct ksmbd_work *);
};
```
**Assessment**: Reasonable for version-specific behavior (signing algorithm, encryption). The SMB2.0, SMB3.0, and SMB3.1.1 variants differ mainly in signing/encryption ops.

#### Command Dispatch Table (`struct smb_version_cmds`)
```c
struct smb_version_cmds {
    int (*proc)(struct ksmbd_work *);
};
```
Single table `smb2_0_server_cmds[NUMBER_OF_SMB2_COMMANDS]` shared by all SMB2/3 versions. 19 command handlers.

### 1.5 Entry Points

1. **Module init**: `server.c:ksmbd_server_init()` -- registers sysfs control interface
2. **Server startup**: Triggered by `ksmbd.mountd` via netlink `KSMBD_EVENT_STARTING_UP`
   - `server.c:server_queue_ctrl_init_work()` -> `server_ctrl_handle_init()` -> `ksmbd_tcp_init()` / `ksmbd_rdma_init()`
3. **Connection accept**: `transport_tcp.c:ksmbd_kthread_fn()` -> `kernel_accept()` -> `ksmbd_tcp_new_connection()` -> `kthread_run(ksmbd_conn_handler_loop)`
4. **Request dispatch**: `connection.c:ksmbd_conn_handler_loop()` reads PDU -> queues `ksmbd_work` -> `handle_ksmbd_work()` -> `conn->cmds[cmd].proc(work)`
5. **Server shutdown**: Triggered via sysfs or netlink `KSMBD_EVENT_SHUTTING_DOWN`

### 1.6 Hot Path Analysis

#### READ Path (most latency-sensitive)
```
ksmbd_conn_handler_loop()
  -> transport.ops->read()           [TCP: kernel_recvmsg]
  -> ksmbd_verify_smb_message()
  -> handle_ksmbd_work()
    -> conn->ops->allocate_rsp_buf()
    -> conn->cmds[SMB2_READ].proc()  = smb2_read()
      -> ksmbd_lookup_fd_fast()      [idr_find under rwlock]
      -> ksmbd_vfs_read()            [kernel_read()]
      -> ksmbd_iov_pin_rsp_read()    [zero-copy response assembly]
    -> conn->ops->set_sign_rsp()     [HMAC/CMAC computation]
    -> conn->ops->encrypt_resp()     [AES-CCM/GCM if encrypted session]
  -> transport.ops->writev()         [TCP: kernel_sendmsg]
```

**Critical observations**:
- File handle lookup via `ksmbd_lookup_fd_fast()` uses `idr_find()` under `rwlock_t` -- fast path, no allocation
- `ksmbd_vfs_read()` calls `kernel_read()` directly -- single copy into response buffer
- Response assembly via `ksmbd_iov_pin_rsp_read()` builds scatter-gather iov without copying
- Signing is on the hot path when enabled -- unavoidable per-packet HMAC/CMAC
- Encryption wraps the entire response -- unavoidable per-packet AES

#### WRITE Path
```
smb2_write()
  -> ksmbd_lookup_fd_fast()
  -> ksmbd_vfs_write()               [kernel_write()]
  -> ksmbd_iov_pin_rsp()             [response header only]
```

**Key insight for modularization**: The READ/WRITE hot paths touch only `vfs.c`, `vfs_cache.c`, `ksmbd_work.c`, `connection.c`, and the transport ops. Any hook system MUST NOT add overhead to these paths unless hooks are actually registered.

### 1.7 Shared Global Data Structures

| Symbol | File | Type | Access Pattern |
|--------|------|------|---------------|
| `server_conf` | `server.h` | `struct ksmbd_server_config` | Read by many, written at startup/reset |
| `conn_list` | `connection.c` | `DECLARE_HASHTABLE` | Per-connection insert/remove, read for IP limiting |
| `conn_list_lock` | `connection.c` | `struct rw_semaphore` | Global connection list lock |
| `ksmbd_debug_types` | `glob.h` | `int` | Read on every debug call |
| `lease_list` (global) | `oplock.c` | `struct list_head` | Oplock/lease table |
| `inode_hash_table` | `vfs_cache.c` | hash table | Inode dedup tracking |
| `global_ft` | `vfs_cache.c` | `struct ksmbd_file_table` | Global file table for durable handles |

---

## Phase 2: Modular Architecture Design

### 2.1 Core Module (`ksmbd-core`)

The core module MUST contain everything on the hot path plus the minimal framework for connection handling and protocol dispatch. It provides the hook infrastructure and registration APIs but ships with no optional features.

#### Files that MUST stay in core:

| File | Reason |
|------|--------|
| `server.c/h` | Module init/exit, global config, server state machine |
| `connection.c/h` | Connection lifecycle, request dispatch loop |
| `smb2pdu.c/h` | All 19 SMB2/3 command handlers (including IOCTL dispatch) |
| `smb2ops.c` | Protocol version ops tables and command dispatch tables |
| `smb2misc.c` | SMB2 header validation |
| `smb_common.c/h` | Protocol negotiation, shared mode checks, fsid override |
| `vfs.c/h` | VFS wrapper operations (hot path) |
| `vfs_cache.c/h` | File handle table, inode hash (hot path) |
| `oplock.c/h` | Oplock/lease (tightly coupled to CREATE/CLOSE/READ/WRITE) |
| `ksmbd_work.c/h` | Work queue, request lifecycle |
| `crypto_ctx.c/h` | Crypto context pool |
| `unicode.c/h` | UTF-8/UTF-16 conversion |
| `misc.c/h` | Utility functions |
| `ndr.c/h` | DOS attribute encoding (used by VFS xattr operations) |
| `compat.c/h` | Kernel version compatibility |
| `mgmt/*` | Session, tree, share, user management |
| `ksmbd_netlink.h` | Netlink ABI (stable userspace ABI) |
| `transport_ipc.c/h` | Netlink IPC (always needed for ksmbd.mountd) |

**Rationale**: Oplock/lease cannot be extracted because it is called from `smb2_open()`, `smb2_read()`, `smb2_write()`, and `smb2_close()` on every operation. The VFS layer is similarly inseparable. The management layer is small and always needed.

### 2.2 Extension Module Registry

The core provides a registration framework for extension modules. This follows established kernel patterns:

- **Netfilter**: `nf_register_net_hook()` with priority-ordered chain
- **Filesystem**: `register_filesystem()` with ops struct
- **Crypto API**: `crypto_register_alg()` with algorithm descriptor

#### Core Registry Header: `ksmbd_extension.h`

```c
/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __KSMBD_EXTENSION_H__
#define __KSMBD_EXTENSION_H__

#include <linux/list.h>
#include <linux/module.h>

struct ksmbd_work;
struct ksmbd_conn;
struct ksmbd_session;
struct ksmbd_file;

/*
 * Extension module descriptor.
 * Each loadable extension registers one of these with the core.
 */
struct ksmbd_extension {
    const char          *name;
    struct module       *owner;
    int                 (*init)(void);
    void                (*exit)(void);

    /*
     * caps_advertise: called during NEGOTIATE to let the extension
     * contribute negotiate context or capability bits.
     * Return 0 on success, negative errno to suppress.
     */
    int (*caps_advertise)(struct ksmbd_conn *conn, void *neg_rsp);

    /*
     * conn_init: called when a new connection is established.
     * Extensions can allocate per-connection state.
     */
    int (*conn_init)(struct ksmbd_conn *conn);

    /*
     * conn_free: called when a connection is torn down.
     * Extensions must free their per-connection state.
     */
    void (*conn_free)(struct ksmbd_conn *conn);

    struct list_head    list;
};

int ksmbd_register_extension(struct ksmbd_extension *ext);
void ksmbd_unregister_extension(struct ksmbd_extension *ext);

/* Iterator for core to call all extensions */
int ksmbd_extensions_conn_init(struct ksmbd_conn *conn);
void ksmbd_extensions_conn_free(struct ksmbd_conn *conn);

#endif /* __KSMBD_EXTENSION_H__ */
```

### 2.3 Hook System Design

Inspired by netfilter's hook chain, but optimized for the ksmbd use case where most hook points will have zero or one handler registered.

#### Design Principles:
1. **Zero overhead when no hooks registered**: Use `static_key` (jump label) to skip hook invocation entirely
2. **No dynamic allocation on hot path**: Hook list is modified only at module load/unload
3. **Priority ordering**: Multiple hooks at the same point execute in priority order
4. **Verdict-based**: Hooks return CONTINUE, HANDLED, or ERROR

```c
/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __KSMBD_HOOKS_H__
#define __KSMBD_HOOKS_H__

#include <linux/list.h>
#include <linux/static_key.h>

struct ksmbd_work;
struct ksmbd_conn;

/*
 * Hook points in the ksmbd request processing pipeline.
 * Naming: KSMBD_HOOK_{PRE|POST}_{OPERATION}
 */
enum ksmbd_hook_point {
    /* Connection lifecycle */
    KSMBD_HOOK_CONN_ESTABLISHED,
    KSMBD_HOOK_CONN_CLOSING,

    /* Protocol negotiation */
    KSMBD_HOOK_PRE_NEGOTIATE,
    KSMBD_HOOK_POST_NEGOTIATE,

    /* Session setup */
    KSMBD_HOOK_PRE_SESSION_SETUP,
    KSMBD_HOOK_POST_SESSION_SETUP,

    /* Tree connect */
    KSMBD_HOOK_PRE_TREE_CONNECT,
    KSMBD_HOOK_POST_TREE_CONNECT,

    /* File operations */
    KSMBD_HOOK_PRE_CREATE,
    KSMBD_HOOK_POST_CREATE,
    KSMBD_HOOK_PRE_CLOSE,
    KSMBD_HOOK_POST_CLOSE,
    KSMBD_HOOK_PRE_READ,
    KSMBD_HOOK_POST_READ,
    KSMBD_HOOK_PRE_WRITE,
    KSMBD_HOOK_POST_WRITE,
    KSMBD_HOOK_PRE_FLUSH,

    /* Directory operations */
    KSMBD_HOOK_PRE_QUERY_DIR,
    KSMBD_HOOK_POST_QUERY_DIR,
    KSMBD_HOOK_READDIR_ENTRY,

    /* Information operations */
    KSMBD_HOOK_PRE_QUERY_INFO,
    KSMBD_HOOK_POST_QUERY_INFO,
    KSMBD_HOOK_PRE_SET_INFO,
    KSMBD_HOOK_POST_SET_INFO,

    /* Lock operations */
    KSMBD_HOOK_PRE_LOCK,
    KSMBD_HOOK_POST_LOCK,

    /* Oplock/lease */
    KSMBD_HOOK_OPLOCK_BREAK,

    /* IOCTL/FSCTL (before the switch statement) */
    KSMBD_HOOK_PRE_IOCTL,

    /* Change notify */
    KSMBD_HOOK_CHANGE_NOTIFY,

    /* Permission checks */
    KSMBD_HOOK_CHECK_ACCESS,

    /* Audit point (after every completed operation) */
    KSMBD_HOOK_AUDIT,

    __KSMBD_HOOK_MAX,
};

#define KSMBD_HOOK_MAX __KSMBD_HOOK_MAX

/*
 * Hook verdicts
 */
enum ksmbd_hook_verdict {
    KSMBD_HOOK_CONTINUE = 0,    /* Continue processing */
    KSMBD_HOOK_HANDLED  = 1,    /* Hook handled the operation, skip default */
    KSMBD_HOOK_ERROR    = -1,   /* Error, abort with work->hdr.Status set */
};

/*
 * Hook context passed to all hook handlers.
 * Provides access to work item and operation-specific data.
 */
struct ksmbd_hook_ctx {
    struct ksmbd_work   *work;
    enum ksmbd_hook_point point;
    int                 status;     /* NTSTATUS from preceding operation */
    void                *data;      /* Hook-point-specific data */
    size_t              data_len;
};

/*
 * Hook registration structure.
 * Priority: lower number = higher priority (runs first).
 * Suggested ranges:
 *   0-99:   Security/ACL hooks (run first)
 *   100-199: Feature hooks (DFS, VSS, Fruit)
 *   200-299: Audit/logging hooks (run last)
 */
struct ksmbd_hook {
    enum ksmbd_hook_point   point;
    int                     priority;
    struct module           *owner;
    int (*handler)(struct ksmbd_hook_ctx *ctx);
    struct list_head        list;
};

/*
 * Registration functions.
 * Thread-safe. Can be called from module init/exit.
 */
int ksmbd_register_hook(struct ksmbd_hook *hook);
void ksmbd_unregister_hook(struct ksmbd_hook *hook);

/*
 * Invocation function (called by core).
 * Returns KSMBD_HOOK_CONTINUE if no hooks registered or all returned CONTINUE.
 * Returns KSMBD_HOOK_HANDLED if any hook handled the operation.
 * Returns KSMBD_HOOK_ERROR if any hook returned ERROR.
 *
 * Uses static_key to skip invocation entirely when no hooks are registered
 * for a given hook point -- zero overhead on hot paths.
 */
int ksmbd_invoke_hooks(enum ksmbd_hook_point point,
                       struct ksmbd_hook_ctx *ctx);

/*
 * Per-hook-point static keys for zero-overhead bypass.
 * Enabled only when at least one hook is registered for that point.
 */
extern struct static_key_false ksmbd_hook_active[KSMBD_HOOK_MAX];

/*
 * Convenience macro for hot-path hook invocation.
 * Compiles to a NOP when no hooks are registered.
 */
#define KSMBD_RUN_HOOKS(point, work, data_ptr, data_sz)         \
({                                                               \
    int __verdict = KSMBD_HOOK_CONTINUE;                         \
    if (static_branch_unlikely(&ksmbd_hook_active[(point)])) {   \
        struct ksmbd_hook_ctx __ctx = {                          \
            .work = (work),                                      \
            .point = (point),                                    \
            .data = (data_ptr),                                  \
            .data_len = (data_sz),                               \
        };                                                       \
        __verdict = ksmbd_invoke_hooks((point), &__ctx);         \
    }                                                            \
    __verdict;                                                   \
})

#endif /* __KSMBD_HOOKS_H__ */
```

### 2.4 Proposed Extension Modules

---

#### Module 1: `ksmbd-transport-tcp`

| Property | Value |
|----------|-------|
| **Priority** | P0 (extract first) |
| **Complexity** | S (Small) |
| **Dependencies** | Core only |
| **Performance Impact** | Zero (already behind ops indirection) |

**Current state**: `transport_tcp.c` is already cleanly separated behind `struct ksmbd_transport_ops`. It only needs to become a separate `.ko`.

**Interface**:
```c
/* ksmbd_transport.h -- provided by core */

struct ksmbd_transport;
struct ksmbd_conn;

struct ksmbd_transport_ops {
    int  (*read)(struct ksmbd_transport *t, char *buf,
                 unsigned int to_read, int max_retries);
    int  (*writev)(struct ksmbd_transport *t, struct kvec *iov,
                   int nvecs, int size, bool need_invalidate,
                   unsigned int remote_key);
    void (*disconnect)(struct ksmbd_transport *t);
    void (*free_transport)(struct ksmbd_transport *t);
};

struct ksmbd_transport {
    struct ksmbd_conn           *conn;
    const struct ksmbd_transport_ops *ops;
};

/*
 * Transport registration API.
 * A transport module calls this to tell the core how to accept connections.
 */
struct ksmbd_transport_handler {
    const char      *name;          /* "tcp", "rdma" */
    struct module   *owner;
    int  (*init)(void);             /* start listening */
    void (*stop)(void);             /* stop accepting */
    void (*destroy)(void);          /* cleanup */

    /*
     * The transport calls ksmbd_conn_alloc() to create a connection,
     * then starts ksmbd_conn_handler_loop() in a kthread.
     * These are EXPORT_SYMBOL_GPL from core.
     */

    struct list_head list;
};

/* Core exports for transport modules */
int ksmbd_register_transport(struct ksmbd_transport_handler *handler);
void ksmbd_unregister_transport(struct ksmbd_transport_handler *handler);

/* Core functions that transport modules call */
struct ksmbd_conn *ksmbd_conn_alloc(void);
void ksmbd_conn_free(struct ksmbd_conn *conn);
int ksmbd_conn_handler_loop(void *p);
bool ksmbd_conn_alive(struct ksmbd_conn *conn);
bool ksmbd_conn_need_reconnect(struct ksmbd_conn *conn);
void ksmbd_free_transport(struct ksmbd_transport *t);
```

**Module implementation sketch** (`ksmbd_transport_tcp.c`):
```c
static struct ksmbd_transport_handler tcp_handler = {
    .name    = "tcp",
    .owner   = THIS_MODULE,
    .init    = ksmbd_tcp_init,
    .stop    = ksmbd_tcp_stop_listening,
    .destroy = ksmbd_tcp_destroy,
};

static int __init ksmbd_tcp_module_init(void)
{
    return ksmbd_register_transport(&tcp_handler);
}

static void __exit ksmbd_tcp_module_exit(void)
{
    ksmbd_unregister_transport(&tcp_handler);
}

module_init(ksmbd_tcp_module_init);
module_exit(ksmbd_tcp_module_exit);
MODULE_LICENSE("GPL");
```

---

#### Module 2: `ksmbd-transport-rdma`

| Property | Value |
|----------|-------|
| **Priority** | P0 |
| **Complexity** | S |
| **Dependencies** | Core, RDMA subsystem |
| **Performance Impact** | Zero (already conditional) |

**Current state**: `transport_rdma.c` is already conditionally compiled via `CONFIG_SMB_SERVER_SMBDIRECT` with clean stubs in `transport_rdma.h`. This is the easiest extraction.

**Additional APIs beyond transport**:
```c
/* RDMA-specific extensions to the transport interface */
struct ksmbd_rdma_ops {
    struct ksmbd_transport_ops  base_ops;

    /* RDMA buffer registration for zero-copy */
    int  (*register_buffer)(struct ksmbd_transport *t,
                            void *buf, size_t len, u32 *rkey);
    void (*deregister_buffer)(struct ksmbd_transport *t, u32 rkey);

    /* SMB Direct negotiation parameters */
    unsigned int (*get_max_read_write_size)(void);
    void (*set_max_io_size)(unsigned int sz);
};

/* Exported by RDMA module, queried by core for RDMA-capable interfaces */
bool ksmbd_rdma_capable_netdev(struct net_device *netdev);
```

---

#### Module 3: `ksmbd-auth-ntlm`

| Property | Value |
|----------|-------|
| **Priority** | P1 |
| **Complexity** | M (Medium) |
| **Dependencies** | Core, crypto subsystem |
| **Performance Impact** | One indirect call per session setup (not hot path) |

**Current state**: All authentication code is in `auth.c` -- NTLM, NTLMv2, and Kerberos (SPNEGO via IPC). The functions are called from `smb2_sess_setup()` in `smb2pdu.c`.

**Proposed interface**:
```c
/* ksmbd_auth.h -- provided by core */

struct ksmbd_conn;
struct ksmbd_session;

/*
 * Authentication method descriptor.
 * Multiple auth methods can be registered simultaneously.
 * The core tries them in priority order during session setup.
 */
struct ksmbd_auth_ops {
    const char      *name;          /* "ntlmv2", "kerberos" */
    struct module   *owner;
    int             priority;       /* Lower = tried first */

    /*
     * negotiate: Contribute to NEGOTIATE response.
     * Called to advertise supported auth mechanisms.
     * For NTLM: advertises NTLMSSP in security blob.
     * For Kerberos: advertises SPNEGO OIDs.
     */
    int (*negotiate)(struct ksmbd_conn *conn, void *neg_rsp_blob,
                     size_t *blob_len);

    /*
     * authenticate: Process SESSION_SETUP request.
     * Receives the security blob from the client.
     * Returns 0 on success (session fully authenticated),
     * -EAGAIN for multi-round auth (more rounds needed),
     * negative errno on failure.
     *
     * On success, must populate sess->user and session keys.
     */
    int (*authenticate)(struct ksmbd_conn *conn,
                        struct ksmbd_session *sess,
                        void *in_blob, size_t in_len,
                        void **out_blob, size_t *out_len);

    /*
     * derive_signing_key: Generate per-session signing key.
     * Called after successful authentication.
     */
    int (*derive_signing_key)(struct ksmbd_session *sess,
                              struct ksmbd_conn *conn);

    /*
     * derive_encryption_key: Generate per-session encryption keys.
     * Called for SMB3+ encrypted sessions.
     */
    int (*derive_encryption_key)(struct ksmbd_conn *conn,
                                 struct ksmbd_session *sess);

    /*
     * sign_request / verify_signature: Per-packet signing.
     * These are on the hot path when signing is enabled.
     * Core can cache the function pointer after session setup
     * to avoid registry lookup overhead.
     */
    int (*sign_response)(struct ksmbd_work *work);
    int (*verify_signature)(struct ksmbd_work *work);

    struct list_head list;
};

int ksmbd_register_auth(struct ksmbd_auth_ops *ops);
void ksmbd_unregister_auth(struct ksmbd_auth_ops *ops);

/*
 * Core helper: find registered auth method by name.
 * Used during negotiate to match client-requested mechanisms.
 */
struct ksmbd_auth_ops *ksmbd_find_auth(const char *name);
void ksmbd_put_auth(struct ksmbd_auth_ops *ops);

/*
 * Functions exported by core for auth modules to use:
 */
/* Crypto context pool access */
struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_hmacmd5(void);
struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_hmacsha256(void);
struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_cmacaes(void);
struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_sha256(void);
struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_sha512(void);
struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_md4(void);
struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_md5(void);
void ksmbd_release_crypto_ctx(struct ksmbd_crypto_ctx *ctx);

/* IPC to userspace daemon */
struct ksmbd_login_response *ksmbd_ipc_login_request(const char *account);
struct ksmbd_spnego_authen_response *
ksmbd_ipc_spnego_authen_request(const char *blob, int blob_len);
```

**Signing hot-path optimization**: After session setup, the core caches the `sign_response` and `verify_signature` function pointers directly in `conn->ops->set_sign_rsp` and `conn->ops->check_sign_req`. This avoids a registry lookup on every packet.

---

#### Module 4: `ksmbd-auth-krb5`

| Property | Value |
|----------|-------|
| **Priority** | P2 |
| **Complexity** | M |
| **Dependencies** | Core, ASN.1 subsystem, ksmbd.mountd |
| **Performance Impact** | Same as NTLM (session setup only) |

Same `struct ksmbd_auth_ops` interface. Implementation forwards SPNEGO blobs to ksmbd.mountd via `ksmbd_ipc_spnego_authen_request()`. The ASN.1 files (`asn1.c`, `ksmbd_spnego_negtokeninit.asn1`, `ksmbd_spnego_negtokentarg.asn1`) would move into this module.

---

#### Module 5: `ksmbd-fruit` (Apple Extensions)

| Property | Value |
|----------|-------|
| **Priority** | P1 |
| **Complexity** | M |
| **Dependencies** | Core |
| **Performance Impact** | One static_key check per CREATE/QUERY_DIR when no hooks registered |

**Current state**: Already behind `CONFIG_KSMBD_FRUIT` with good stub separation. The `smb2fruit.c/h` files contain the implementation.

**Integration points in core** (requires hooks):
1. `smb2_open()` -- AAPL create context parsing and response
2. `smb2_populate_readdir_entry()` -- ReadDirAttr enrichment
3. `smb2_query_info()` -- Apple-specific info levels
4. `smb2_negotiate()` -- fruit model string in NEGOTIATE response

**Interface using hook system**:
```c
/* ksmbd_fruit_module.c */

static int fruit_create_hook(struct ksmbd_hook_ctx *ctx)
{
    struct smb2_create_req *req = ctx->data;
    struct ksmbd_conn *conn = ctx->work->conn;
    struct create_context *aapl_ctx;

    if (!conn->is_fruit)
        return KSMBD_HOOK_CONTINUE;

    aapl_ctx = smb2_find_context_vals(req, SMB2_CREATE_AAPL, 4);
    if (!aapl_ctx || IS_ERR(aapl_ctx))
        return KSMBD_HOOK_CONTINUE;

    /* Process AAPL create context */
    return fruit_process_create_context(ctx->work, aapl_ctx);
}

static int fruit_readdir_hook(struct ksmbd_hook_ctx *ctx)
{
    /* Enrich directory entries with UNIX mode in EaSize */
    struct readdir_hook_data *rd = ctx->data;

    if (!ctx->work->conn->is_fruit)
        return KSMBD_HOOK_CONTINUE;

    smb2_read_dir_attr_fill(ctx->work->conn, rd->dentry,
                            rd->stat, rd->share, rd->ea_size_field);
    return KSMBD_HOOK_CONTINUE;
}

static struct ksmbd_hook fruit_hooks[] = {
    {
        .point    = KSMBD_HOOK_POST_CREATE,
        .priority = 100,
        .owner    = THIS_MODULE,
        .handler  = fruit_create_hook,
    },
    {
        .point    = KSMBD_HOOK_READDIR_ENTRY,
        .priority = 100,
        .owner    = THIS_MODULE,
        .handler  = fruit_readdir_hook,
    },
};

static struct ksmbd_extension fruit_ext = {
    .name      = "fruit",
    .owner     = THIS_MODULE,
    .init      = fruit_init_module,
    .exit      = fruit_cleanup_module,
    .conn_init = fruit_conn_init,
    .conn_free = fruit_conn_free,
};

static int __init ksmbd_fruit_module_init(void)
{
    int i, rc;

    rc = ksmbd_register_extension(&fruit_ext);
    if (rc)
        return rc;

    for (i = 0; i < ARRAY_SIZE(fruit_hooks); i++) {
        rc = ksmbd_register_hook(&fruit_hooks[i]);
        if (rc)
            goto err;
    }
    return 0;
err:
    while (--i >= 0)
        ksmbd_unregister_hook(&fruit_hooks[i]);
    ksmbd_unregister_extension(&fruit_ext);
    return rc;
}
```

---

#### Module 6: `ksmbd-dfs` (Distributed File System)

| Property | Value |
|----------|-------|
| **Priority** | P2 |
| **Complexity** | L (Large) |
| **Dependencies** | Core |
| **Performance Impact** | One FSCTL handler lookup per DFS referral request |

**Current state**: DFS is stubbed out (`FSCTL_DFS_GET_REFERRALS` returns `-EOPNOTSUPP` in `smb2_ioctl()`).

**Interface**:
```c
/* ksmbd_dfs.h */

struct ksmbd_dfs_ops {
    /*
     * get_referral: Handle FSCTL_DFS_GET_REFERRALS.
     * Populates the referral response buffer.
     */
    int (*get_referral)(struct ksmbd_work *work,
                        const char *path,
                        void *rsp_buf, size_t *rsp_len);

    /*
     * get_referral_ex: Handle FSCTL_DFS_GET_REFERRALS_EX.
     * Extended referral with additional flags.
     */
    int (*get_referral_ex)(struct ksmbd_work *work,
                           const void *req_buf, size_t req_len,
                           void *rsp_buf, size_t *rsp_len);

    /*
     * resolve_path: Resolve a DFS path to a local path.
     * Called during tree connect and file open.
     */
    int (*resolve_path)(struct ksmbd_conn *conn,
                        const char *dfs_path,
                        char *resolved_path, size_t resolved_len);

    /*
     * is_dfs_share: Check if a share is a DFS root.
     */
    bool (*is_dfs_share)(struct ksmbd_share_config *share);
};

int ksmbd_register_dfs(struct ksmbd_dfs_ops *ops);
void ksmbd_unregister_dfs(struct ksmbd_dfs_ops *ops);
```

---

#### Module 7: `ksmbd-vss` (Volume Shadow Copy / Snapshots)

| Property | Value |
|----------|-------|
| **Priority** | P2 |
| **Complexity** | L |
| **Dependencies** | Core, filesystem backend (btrfs/ZFS/LVM) |
| **Performance Impact** | Path resolution overhead for @GMT tokens |

**Current state**: Not implemented.

**Interface**:
```c
/* ksmbd_vss.h */

struct ksmbd_vss_ops {
    /*
     * enumerate_snapshots: Handle FSCTL_SRV_ENUMERATE_SNAPSHOTS.
     * Returns list of available snapshots (as @GMT-formatted strings).
     */
    int (*enumerate_snapshots)(struct ksmbd_work *work,
                               struct ksmbd_file *fp,
                               void *rsp_buf, size_t *rsp_len);

    /*
     * resolve_gmt_path: Convert a @GMT-token path to a real path.
     * E.g., "share\@GMT-2026.02.22-10.00.00\file.txt" ->
     *        "/mnt/share/.snapshots/2026-02-22/file.txt"
     */
    int (*resolve_gmt_path)(struct ksmbd_share_config *share,
                            const char *gmt_path,
                            char *resolved_path, size_t resolved_len);

    /*
     * is_snapshot_path: Check if a path contains a @GMT token.
     */
    bool (*is_snapshot_path)(const char *path);
};

/*
 * Snapshot backend abstraction.
 * Different filesystem backends register their implementation.
 */
struct ksmbd_snapshot_backend {
    const char      *name;          /* "btrfs", "zfs", "lvm" */
    struct module   *owner;

    int (*list_snapshots)(const struct path *share_path,
                          char **snap_list, int *snap_count);
    int (*get_snapshot_path)(const struct path *share_path,
                            const char *gmt_token,
                            struct path *snap_path);

    struct list_head list;
};

int ksmbd_register_vss(struct ksmbd_vss_ops *ops);
void ksmbd_unregister_vss(struct ksmbd_vss_ops *ops);
int ksmbd_register_snapshot_backend(struct ksmbd_snapshot_backend *be);
void ksmbd_unregister_snapshot_backend(struct ksmbd_snapshot_backend *be);
```

---

#### Module 8: `ksmbd-compress` (SMB Compression)

| Property | Value |
|----------|-------|
| **Priority** | P3 |
| **Complexity** | XL |
| **Dependencies** | Core, kernel compression algorithms |
| **Performance Impact** | Per-packet compression/decompression on data path |

**Current state**: Compression transform headers are detected and rejected in `ksmbd_smb_request()`:
```c
if (*proto == SMB2_COMPRESSION_TRANSFORM_ID) {
    pr_err_ratelimited("smb2 compression not support yet");
    return false;
}
```

**Interface**:
```c
/* ksmbd_compress.h */

/*
 * Compression algorithm descriptor.
 * Multiple algorithms can be registered; negotiate selects one.
 */
struct ksmbd_compress_algo {
    const char      *name;          /* "lz77", "lz77+huffman", "lznt1" */
    struct module   *owner;
    u16             algorithm_id;   /* SMB2 compression algorithm ID */
    int             priority;       /* Preference order */

    int (*compress)(const void *in, size_t in_len,
                    void *out, size_t *out_len);
    int (*decompress)(const void *in, size_t in_len,
                      void *out, size_t out_len);

    struct list_head list;
};

struct ksmbd_compress_ops {
    /*
     * negotiate_context: Build SMB2_COMPRESSION_CAPABILITIES
     * negotiate context for NEGOTIATE response.
     */
    int (*negotiate_context)(struct ksmbd_conn *conn,
                             void *neg_ctx_buf, size_t *ctx_len);

    /*
     * transform_request: Decompress an incoming compressed request.
     * Called before command dispatch.
     */
    int (*transform_request)(struct ksmbd_work *work);

    /*
     * transform_response: Compress an outgoing response.
     * Called after command handler, before signing/encryption.
     */
    int (*transform_response)(struct ksmbd_work *work);
};

int ksmbd_register_compress_algo(struct ksmbd_compress_algo *algo);
void ksmbd_unregister_compress_algo(struct ksmbd_compress_algo *algo);
int ksmbd_register_compress(struct ksmbd_compress_ops *ops);
void ksmbd_unregister_compress(struct ksmbd_compress_ops *ops);
```

---

#### Module 9: `ksmbd-acl` (Advanced ACL Engine)

| Property | Value |
|----------|-------|
| **Priority** | P1 |
| **Complexity** | L |
| **Dependencies** | Core |
| **Performance Impact** | Per-file-open permission check (moderate path) |

**Current state**: `smbacl.c` implements Windows-to-POSIX ACL translation. It is called from `smb2_open()`, `smb2_set_info()`, and `smb2_query_info()`.

**Design decision**: Keep basic `build_sec_desc()`/`parse_sec_desc()` in core (they are needed for basic `QUERY_INFO`/`SET_INFO` security descriptor operations). The advanced ACL module adds:
- Rich ACL support
- ACL inheritance engine
- ACL storage backend abstraction
- SID-to-UID/GID mapping policies

**Interface**:
```c
/* ksmbd_acl.h */

struct ksmbd_acl_ops {
    /*
     * check_access: Enhanced permission check beyond POSIX.
     * Called from smb2_open() after basic VFS permission checks.
     * Return 0 to allow, -EACCES to deny.
     */
    int (*check_access)(struct ksmbd_work *work,
                        const struct path *path,
                        __le32 desired_access,
                        __le32 *granted_access);

    /*
     * inherit_acl: Compute ACLs for a newly created file/directory
     * based on parent ACLs and creation parameters.
     */
    int (*inherit_acl)(struct ksmbd_conn *conn,
                       const struct path *parent_path,
                       const struct path *child_path,
                       bool is_dir);

    /*
     * translate_acl: Convert between Windows NTSD and POSIX ACL.
     * direction: 0 = NTSD->POSIX, 1 = POSIX->NTSD
     */
    int (*translate_acl)(struct ksmbd_conn *conn,
                         const struct path *path,
                         struct smb_ntsd *ntsd, int ntsd_len,
                         int direction);

    /*
     * sid_to_id: Map a Windows SID to a UNIX uid/gid.
     * Allows pluggable mapping policies (idmap, AD, static).
     */
    int (*sid_to_id)(const struct smb_sid *sid,
                     unsigned int *uid, unsigned int *gid);

    /*
     * id_to_sid: Map a UNIX uid/gid to a Windows SID.
     */
    int (*id_to_sid)(unsigned int id, uint sidtype,
                     struct smb_sid *sid);
};

int ksmbd_register_acl(struct ksmbd_acl_ops *ops);
void ksmbd_unregister_acl(struct ksmbd_acl_ops *ops);
```

---

#### Module 10: `ksmbd-audit` (Audit/Logging)

| Property | Value |
|----------|-------|
| **Priority** | P2 |
| **Complexity** | M |
| **Dependencies** | Core, kernel audit framework |
| **Performance Impact** | Per-operation audit record (but only when hook registered) |

**Interface**:
```c
/* ksmbd_audit.h */

enum ksmbd_audit_event {
    KSMBD_AUDIT_CONNECT,
    KSMBD_AUDIT_DISCONNECT,
    KSMBD_AUDIT_LOGON,
    KSMBD_AUDIT_LOGON_FAIL,
    KSMBD_AUDIT_LOGOFF,
    KSMBD_AUDIT_TREE_CONNECT,
    KSMBD_AUDIT_TREE_DISCONNECT,
    KSMBD_AUDIT_FILE_OPEN,
    KSMBD_AUDIT_FILE_CLOSE,
    KSMBD_AUDIT_FILE_READ,
    KSMBD_AUDIT_FILE_WRITE,
    KSMBD_AUDIT_FILE_RENAME,
    KSMBD_AUDIT_FILE_DELETE,
    KSMBD_AUDIT_DIR_LIST,
    KSMBD_AUDIT_SET_INFO,
    KSMBD_AUDIT_SET_ACL,
    KSMBD_AUDIT_LOCK,
    KSMBD_AUDIT_IOCTL,
};

struct ksmbd_audit_record {
    enum ksmbd_audit_event  event;
    ktime_t                 timestamp;
    u64                     session_id;
    u32                     tree_id;
    u32                     client_ip;      /* or ipv6 */
    const char              *username;
    const char              *share_name;
    const char              *filename;
    __le32                  status;         /* NTSTATUS result */
    __le32                  access_mask;
    u64                     bytes;          /* for read/write */
};

/*
 * Audit uses the KSMBD_HOOK_AUDIT hook point.
 * The handler receives a ksmbd_audit_record in ctx->data.
 */
```

The audit module registers a single hook at `KSMBD_HOOK_AUDIT` with priority 200. The core emits audit records at the end of each command handler.

---

### 2.5 FSCTL Registration System

The IOCTL/FSCTL handler in `smb2_ioctl()` currently uses a large `switch` statement. The modular design adds a registration mechanism for additional FSCTL codes.

```c
/* ksmbd_fsctl.h -- provided by core */

struct ksmbd_work;

struct ksmbd_fsctl_handler {
    u32             fsctl_code;
    struct module   *owner;
    const char      *name;          /* for debug/sysfs */

    /*
     * handler: Process the FSCTL.
     * Receives the input buffer and output buffer pointers.
     * Must set *out_len to the number of bytes written to out_buf.
     * Return 0 on success, negative errno on failure.
     */
    int (*handler)(struct ksmbd_work *work,
                   u64 volatile_fid,
                   const void *in_buf, u32 in_len,
                   void *out_buf, u32 *out_len);

    struct hlist_node hnode;
};

int ksmbd_register_fsctl(struct ksmbd_fsctl_handler *h);
void ksmbd_unregister_fsctl(struct ksmbd_fsctl_handler *h);

/*
 * Called by smb2_ioctl() for FSCTL codes not in the built-in switch.
 * Returns 0 if a handler was found and executed, -EOPNOTSUPP otherwise.
 */
int ksmbd_dispatch_fsctl(struct ksmbd_work *work,
                         u32 fsctl_code, u64 volatile_fid,
                         const void *in_buf, u32 in_len,
                         void *out_buf, u32 *out_len);
```

**Core integration** (modification to `smb2_ioctl()`):
```c
/* In smb2_ioctl(), after the built-in switch statement: */
default:
    /* Try registered FSCTL handlers from extension modules */
    ret = ksmbd_dispatch_fsctl(work, cnt_code, id,
                               buffer, in_buf_len,
                               &rsp->Buffer[0], &nbytes);
    if (ret == -EOPNOTSUPP) {
        rsp->hdr.Status = STATUS_NOT_SUPPORTED;
        goto out;
    }
    if (ret < 0)
        goto out;
    break;
```

### 2.6 Create Context Registration System

```c
/* ksmbd_create_ctx.h -- provided by core */

struct ksmbd_work;
struct create_context;

struct ksmbd_create_ctx_handler {
    char            name[16];       /* Context name tag (e.g., "AAPL") */
    int             name_len;
    struct module   *owner;

    /*
     * parse_request: Parse create context from client request.
     * Called during smb2_open() when this context tag is found.
     * Return 0 to continue, negative errno to fail the CREATE.
     */
    int (*parse_request)(struct ksmbd_work *work,
                         struct create_context *ctx,
                         void *create_data);

    /*
     * build_response: Add create context to CREATE response.
     * Called after successful file open.
     * *buf points to the next available context slot.
     * *len is updated with bytes consumed.
     * Return 0 on success, -EOPNOTSUPP to skip.
     */
    int (*build_response)(struct ksmbd_work *work,
                          char *buf, int *len,
                          void *create_data);

    struct list_head list;
};

int ksmbd_register_create_ctx(struct ksmbd_create_ctx_handler *h);
void ksmbd_unregister_create_ctx(struct ksmbd_create_ctx_handler *h);

/*
 * Called by smb2_open() for each unrecognized create context.
 * Returns handler if found, NULL otherwise.
 */
struct ksmbd_create_ctx_handler *
ksmbd_find_create_ctx_handler(const char *name, int name_len);
```

### 2.7 Information Level Registration System

```c
/* ksmbd_info_level.h -- provided by core */

struct ksmbd_work;

struct ksmbd_info_handler {
    u8              info_type;      /* SMB2_O_INFO_FILE, _FILESYSTEM, etc. */
    u8              info_class;     /* FileBasicInformation, etc. */
    struct module   *owner;

    /*
     * query: Handle QUERY_INFO for this info type/class.
     * Writes response data to buf, sets *len to bytes written.
     */
    int (*query)(struct ksmbd_work *work,
                 struct ksmbd_file *fp,
                 void *buf, int *len);

    /*
     * set: Handle SET_INFO for this info type/class.
     * Reads request data from buf of length len.
     */
    int (*set)(struct ksmbd_work *work,
               struct ksmbd_file *fp,
               const void *buf, int len);

    struct hlist_node hnode;
};

int ksmbd_register_info_handler(struct ksmbd_info_handler *h);
void ksmbd_unregister_info_handler(struct ksmbd_info_handler *h);

/*
 * Called by smb2_query_info()/smb2_set_info() for unhandled info classes.
 */
int ksmbd_dispatch_query_info(struct ksmbd_work *work,
                              struct ksmbd_file *fp,
                              u8 info_type, u8 info_class,
                              void *buf, int *len);
int ksmbd_dispatch_set_info(struct ksmbd_work *work,
                            struct ksmbd_file *fp,
                            u8 info_type, u8 info_class,
                            const void *buf, int len);
```

---

## Phase 3: API Design Details

### 3.1 Complete Symbol Export List

The core module (`ksmbd-core`) must export these symbols for extension modules:

#### Connection Management
```c
EXPORT_SYMBOL_GPL(ksmbd_conn_alloc);
EXPORT_SYMBOL_GPL(ksmbd_conn_free);
EXPORT_SYMBOL_GPL(ksmbd_conn_handler_loop);
EXPORT_SYMBOL_GPL(ksmbd_conn_alive);
EXPORT_SYMBOL_GPL(ksmbd_conn_need_reconnect);
```

#### Transport Registration
```c
EXPORT_SYMBOL_GPL(ksmbd_register_transport);
EXPORT_SYMBOL_GPL(ksmbd_unregister_transport);
EXPORT_SYMBOL_GPL(ksmbd_free_transport);
```

#### Extension and Hook Registration
```c
EXPORT_SYMBOL_GPL(ksmbd_register_extension);
EXPORT_SYMBOL_GPL(ksmbd_unregister_extension);
EXPORT_SYMBOL_GPL(ksmbd_register_hook);
EXPORT_SYMBOL_GPL(ksmbd_unregister_hook);
EXPORT_SYMBOL_GPL(ksmbd_invoke_hooks);
EXPORT_SYMBOL_GPL(ksmbd_hook_active);  /* static key array */
```

#### FSCTL / Create Context / Info Level Registration
```c
EXPORT_SYMBOL_GPL(ksmbd_register_fsctl);
EXPORT_SYMBOL_GPL(ksmbd_unregister_fsctl);
EXPORT_SYMBOL_GPL(ksmbd_register_create_ctx);
EXPORT_SYMBOL_GPL(ksmbd_unregister_create_ctx);
EXPORT_SYMBOL_GPL(ksmbd_register_info_handler);
EXPORT_SYMBOL_GPL(ksmbd_unregister_info_handler);
```

#### Authentication Registration
```c
EXPORT_SYMBOL_GPL(ksmbd_register_auth);
EXPORT_SYMBOL_GPL(ksmbd_unregister_auth);
EXPORT_SYMBOL_GPL(ksmbd_find_auth);
EXPORT_SYMBOL_GPL(ksmbd_put_auth);
```

#### Crypto Context Pool (for auth modules)
```c
EXPORT_SYMBOL_GPL(ksmbd_crypto_ctx_find_hmacmd5);
EXPORT_SYMBOL_GPL(ksmbd_crypto_ctx_find_hmacsha256);
EXPORT_SYMBOL_GPL(ksmbd_crypto_ctx_find_cmacaes);
EXPORT_SYMBOL_GPL(ksmbd_crypto_ctx_find_sha256);
EXPORT_SYMBOL_GPL(ksmbd_crypto_ctx_find_sha512);
EXPORT_SYMBOL_GPL(ksmbd_crypto_ctx_find_md4);
EXPORT_SYMBOL_GPL(ksmbd_crypto_ctx_find_md5);
EXPORT_SYMBOL_GPL(ksmbd_crypto_ctx_find_gcm);
EXPORT_SYMBOL_GPL(ksmbd_crypto_ctx_find_ccm);
EXPORT_SYMBOL_GPL(ksmbd_release_crypto_ctx);
```

#### IPC (for auth modules that need userspace daemon)
```c
EXPORT_SYMBOL_GPL(ksmbd_ipc_login_request);
EXPORT_SYMBOL_GPL(ksmbd_ipc_login_request_ext);
EXPORT_SYMBOL_GPL(ksmbd_ipc_spnego_authen_request);
```

#### VFS Helpers (for extension modules that need file operations)
```c
EXPORT_SYMBOL_GPL(ksmbd_vfs_getxattr);
EXPORT_SYMBOL_GPL(ksmbd_vfs_setxattr);
EXPORT_SYMBOL_GPL(ksmbd_vfs_listxattr);
EXPORT_SYMBOL_GPL(ksmbd_vfs_kern_path);
```

#### Work Item Access (for hooks)
```c
EXPORT_SYMBOL_GPL(ksmbd_alloc_work_struct);
EXPORT_SYMBOL_GPL(ksmbd_free_work_struct);
```

#### SMB2 PDU Helpers (for create context handlers)
```c
EXPORT_SYMBOL_GPL(smb2_find_context_vals);
EXPORT_SYMBOL_GPL(smb2_get_msg);
EXPORT_SYMBOL_GPL(smb2_set_err_rsp);
```

#### Debug Infrastructure
```c
EXPORT_SYMBOL_GPL(ksmbd_debug_types);
```

#### Server Config (read-only access for modules)
```c
EXPORT_SYMBOL_GPL(server_conf);
```

### 3.2 Per-Connection Extension State

Extension modules need to store per-connection state. Rather than adding fields to `ksmbd_conn` for each extension, we use a void pointer array indexed by extension ID:

```c
/* In struct ksmbd_conn */
#define KSMBD_MAX_EXTENSIONS 16

struct ksmbd_conn {
    /* ... existing fields ... */

    /*
     * Per-extension private data.
     * Indexed by extension registration order.
     * Set by extension's conn_init(), freed by conn_free().
     */
    void *ext_data[KSMBD_MAX_EXTENSIONS];
};

/* Helper for extensions to access their state */
static inline void *ksmbd_ext_conn_data(struct ksmbd_conn *conn,
                                         struct ksmbd_extension *ext)
{
    return conn->ext_data[ext->id];
}

static inline void ksmbd_ext_set_conn_data(struct ksmbd_conn *conn,
                                            struct ksmbd_extension *ext,
                                            void *data)
{
    conn->ext_data[ext->id] = data;
}
```

This replaces the current `conn->fruit_state` pointer with a generic mechanism that does not require modifying `ksmbd_conn` for each new extension.

### 3.3 Hook Implementation Details

```c
/* ksmbd_hooks.c -- core implementation */

#include "ksmbd_hooks.h"

/* One list per hook point, protected by RCU */
static struct list_head hook_chains[KSMBD_HOOK_MAX];
static DEFINE_MUTEX(hook_mutex);

/* Static keys for zero-overhead bypass */
struct static_key_false ksmbd_hook_active[KSMBD_HOOK_MAX];
EXPORT_SYMBOL_GPL(ksmbd_hook_active);

void __init ksmbd_hooks_init(void)
{
    int i;
    for (i = 0; i < KSMBD_HOOK_MAX; i++)
        INIT_LIST_HEAD(&hook_chains[i]);
}

int ksmbd_register_hook(struct ksmbd_hook *hook)
{
    struct ksmbd_hook *pos;
    bool was_empty;

    if (hook->point >= KSMBD_HOOK_MAX)
        return -EINVAL;

    mutex_lock(&hook_mutex);

    was_empty = list_empty(&hook_chains[hook->point]);

    /* Insert sorted by priority (lower number = earlier execution) */
    list_for_each_entry(pos, &hook_chains[hook->point], list) {
        if (hook->priority < pos->priority) {
            list_add_tail_rcu(&hook->list, &pos->list);
            goto done;
        }
    }
    list_add_tail_rcu(&hook->list, &hook_chains[hook->point]);

done:
    if (was_empty)
        static_branch_enable(&ksmbd_hook_active[hook->point]);

    mutex_unlock(&hook_mutex);
    return 0;
}
EXPORT_SYMBOL_GPL(ksmbd_register_hook);

void ksmbd_unregister_hook(struct ksmbd_hook *hook)
{
    mutex_lock(&hook_mutex);

    list_del_rcu(&hook->list);
    synchronize_rcu();

    if (list_empty(&hook_chains[hook->point]))
        static_branch_disable(&ksmbd_hook_active[hook->point]);

    mutex_unlock(&hook_mutex);
}
EXPORT_SYMBOL_GPL(ksmbd_unregister_hook);

int ksmbd_invoke_hooks(enum ksmbd_hook_point point,
                       struct ksmbd_hook_ctx *ctx)
{
    struct ksmbd_hook *hook;
    int verdict = KSMBD_HOOK_CONTINUE;

    rcu_read_lock();
    list_for_each_entry_rcu(hook, &hook_chains[point], list) {
        if (!try_module_get(hook->owner))
            continue;

        verdict = hook->handler(ctx);
        module_put(hook->owner);

        if (verdict != KSMBD_HOOK_CONTINUE)
            break;
    }
    rcu_read_unlock();

    return verdict;
}
EXPORT_SYMBOL_GPL(ksmbd_invoke_hooks);
```

### 3.4 FSCTL Dispatch Implementation

```c
/* ksmbd_fsctl.c -- core implementation */

#include "ksmbd_fsctl.h"

#define FSCTL_HASH_BITS 6
static DEFINE_HASHTABLE(fsctl_handlers, FSCTL_HASH_BITS);
static DEFINE_MUTEX(fsctl_mutex);

int ksmbd_register_fsctl(struct ksmbd_fsctl_handler *h)
{
    mutex_lock(&fsctl_mutex);
    hash_add(fsctl_handlers, &h->hnode, h->fsctl_code);
    mutex_unlock(&fsctl_mutex);
    return 0;
}
EXPORT_SYMBOL_GPL(ksmbd_register_fsctl);

void ksmbd_unregister_fsctl(struct ksmbd_fsctl_handler *h)
{
    mutex_lock(&fsctl_mutex);
    hash_del(&h->hnode);
    mutex_unlock(&fsctl_mutex);
    synchronize_rcu();
}
EXPORT_SYMBOL_GPL(ksmbd_unregister_fsctl);

int ksmbd_dispatch_fsctl(struct ksmbd_work *work,
                         u32 fsctl_code, u64 volatile_fid,
                         const void *in_buf, u32 in_len,
                         void *out_buf, u32 *out_len)
{
    struct ksmbd_fsctl_handler *h;
    int ret = -EOPNOTSUPP;

    rcu_read_lock();
    hash_for_each_possible_rcu(fsctl_handlers, h, hnode, fsctl_code) {
        if (h->fsctl_code == fsctl_code) {
            if (!try_module_get(h->owner)) {
                ret = -ENODEV;
                break;
            }
            rcu_read_unlock();

            ret = h->handler(work, volatile_fid,
                             in_buf, in_len, out_buf, out_len);

            module_put(h->owner);
            return ret;
        }
    }
    rcu_read_unlock();

    return ret;
}
```

---

## Phase 4: ABI Stability Plan

### 4.1 Symbol Versioning Strategy

All exported symbols use `EXPORT_SYMBOL_GPL` (matching the module's GPL-2.0 license). The versioning strategy:

1. **No symbol versioning initially**: Linux kernel modules do not use ELF symbol versioning. Instead, `CONFIG_MODVERSIONS` provides CRC-based version checks. This is sufficient for in-tree modules.

2. **For out-of-tree builds**: The `Module.symvers` file from the core module build is required to build extension modules. This provides compile-time ABI compatibility checking.

3. **API version constant**:
```c
#define KSMBD_API_VERSION_MAJOR  1
#define KSMBD_API_VERSION_MINOR  0

struct ksmbd_extension {
    /* ... */
    int api_version_major;  /* Must match KSMBD_API_VERSION_MAJOR */
    int api_version_minor;  /* Must be <= KSMBD_API_VERSION_MINOR */
};
```

The core checks `api_version_major` at registration time and rejects mismatches.

### 4.2 Data Structure Stability

#### Structures that are part of the module ABI:

| Structure | Stability Level | Evolution Strategy |
|-----------|----------------|-------------------|
| `struct ksmbd_transport_ops` | Stable | Append-only; new ops get default NULL handler |
| `struct ksmbd_auth_ops` | Stable | Append-only |
| `struct ksmbd_hook` | Stable | Immutable (tiny struct) |
| `struct ksmbd_hook_ctx` | Semi-stable | `data` pointer provides extensibility |
| `struct ksmbd_extension` | Stable | Append-only with reserved fields |
| `struct ksmbd_work` | Internal | Opaque to extensions; access via helpers only |
| `struct ksmbd_conn` | Internal | `ext_data[]` provides extensibility |
| `struct ksmbd_session` | Internal | Opaque to extensions |
| `struct ksmbd_file` | Internal | Opaque to extensions |

#### Rules for struct evolution:

1. **Append-only for ABI structs**: New fields are added at the end. Existing field offsets never change.
2. **Reserved padding**: ABI structs include reserved fields for future expansion:
```c
struct ksmbd_extension {
    /* ... existing fields ... */
    unsigned long reserved[4];  /* For future use */
};
```
3. **Opaque handles for internal structs**: Extension modules access `ksmbd_work`, `ksmbd_conn`, etc. only through exported helper functions, never by directly reading struct fields.

#### Accessor functions for opaque types:

```c
/* Work item accessors -- exported by core */
struct ksmbd_conn *ksmbd_work_conn(struct ksmbd_work *work);
struct ksmbd_session *ksmbd_work_sess(struct ksmbd_work *work);
struct ksmbd_tree_connect *ksmbd_work_tcon(struct ksmbd_work *work);
void *ksmbd_work_request_buf(struct ksmbd_work *work);
void *ksmbd_work_response_buf(struct ksmbd_work *work);

/* Connection accessors */
u16 ksmbd_conn_dialect(struct ksmbd_conn *conn);
bool ksmbd_conn_is_encrypted(struct ksmbd_conn *conn);
```

### 4.3 Deprecation Policy

1. **Minimum 2 kernel releases**: Deprecated APIs remain functional for at least 2 kernel releases after deprecation announcement.
2. **Compile warning**: Deprecated functions are marked with `__deprecated`:
```c
int __deprecated ksmbd_old_api(void);
```
3. **Runtime warning**: Deprecated APIs emit a `pr_warn_once()` when called.
4. **Removal**: After the deprecation period, the API is removed and extensions must update.

### 4.4 Capability Negotiation

Extension modules advertise their capabilities to the core, which uses this information during SMB protocol negotiation:

```c
/* Capability flags that extensions can set */
#define KSMBD_CAP_DFS           BIT(0)
#define KSMBD_CAP_VSS           BIT(1)
#define KSMBD_CAP_FRUIT         BIT(2)
#define KSMBD_CAP_COMPRESS      BIT(3)
#define KSMBD_CAP_ADV_ACL       BIT(4)
#define KSMBD_CAP_AUDIT         BIT(5)

/* Core queries loaded capabilities */
u64 ksmbd_get_loaded_capabilities(void);

/* Extension sets its capabilities at init */
struct ksmbd_extension {
    /* ... */
    u64 capabilities;  /* OR of KSMBD_CAP_* bits */
};
```

During NEGOTIATE, the core checks `ksmbd_get_loaded_capabilities()` to determine which protocol features to advertise. For example, if `KSMBD_CAP_DFS` is not set, the NEGOTIATE response will not include DFS capability flags.

### 4.5 Runtime Feature Toggling

Extensions can be loaded/unloaded at runtime (when built as modules), but the core enforces safety:

1. **No unload while connections active**: An extension cannot be unloaded while any connection has active state for that extension.
2. **Module reference counting**: Hooks use `try_module_get()/module_put()` to prevent unload during hook execution.
3. **Graceful degradation**: If an extension is unloaded, the core falls back to default behavior (e.g., returning `-EOPNOTSUPP` for DFS referrals).

---

## Phase 5: Migration Plan

### 5.1 Step-by-Step Extraction Order

The extraction order is determined by risk (least coupled first) and dependency (infrastructure before features):

#### Step 1: Core Infrastructure (No Module Split Yet)
- Add `ksmbd_extension.h`, `ksmbd_hooks.h`, `ksmbd_fsctl.h`, `ksmbd_create_ctx.h`, `ksmbd_info_level.h` headers
- Implement hook system (`ksmbd_hooks.c`)
- Implement FSCTL dispatch (`ksmbd_fsctl.c`)
- Add `ext_data[]` to `ksmbd_conn`
- Add `EXPORT_SYMBOL_GPL` to all functions that extension modules will need
- Add `KSMBD_RUN_HOOKS()` calls at all hook points in `smb2pdu.c`
- Add `ksmbd_dispatch_fsctl()` fallback in `smb2_ioctl()`
- **Test**: Verify no regression with monolithic build (all features compiled in)

#### Step 2: Extract `ksmbd-transport-tcp` (P0, Complexity: S)
- Move `transport_tcp.c` to a separate module
- Modify `server.c` to not call `ksmbd_tcp_init()` directly; instead use transport registry
- TCP module auto-loads via `MODULE_ALIAS` or explicit `request_module()`
- **Kconfig**: `CONFIG_SMB_SERVER_TCP` (tristate, default y for backward compat)
- **Test**: Boot with TCP as built-in and as module; verify connections work

#### Step 3: Extract `ksmbd-transport-rdma` (P0, Complexity: S)
- Already conditionally compiled; move to separate module
- Remove `CONFIG_SMB_SERVER_SMBDIRECT` from core Kconfig; make it a separate module option
- **Kconfig**: `CONFIG_SMB_SERVER_RDMA` (tristate, depends on INFINIBAND)
- **Test**: Load/unload RDMA module; verify SMB Direct still works

#### Step 4: Extract `ksmbd-fruit` (P1, Complexity: M)
- Move `smb2fruit.c/h` to a separate module
- Replace all `#ifdef CONFIG_KSMBD_FRUIT` in core with hook invocations
- Fruit module registers hooks for POST_CREATE, READDIR_ENTRY, POST_NEGOTIATE
- Fruit module registers AAPL create context handler
- Remove `conn->is_fruit` and `conn->fruit_state`; use `ext_data[]` instead
- **Kconfig**: `CONFIG_SMB_SERVER_FRUIT` (tristate)
- **Test**: macOS client connection with Fruit module loaded and unloaded

#### Step 5: Extract `ksmbd-acl` (P1, Complexity: L)
- Keep basic `build_sec_desc()`/`parse_sec_desc()` in core
- Extract advanced ACL logic (inheritance, rich ACLs) to module
- Module registers CHECK_ACCESS hook
- **Kconfig**: `CONFIG_SMB_SERVER_ADV_ACL` (tristate)
- **Test**: ACL operations with and without module

#### Step 6: Extract `ksmbd-auth-ntlm` (P1, Complexity: M)
- Move NTLM/NTLMv2 specific code from `auth.c` to separate module
- Keep crypto helper infrastructure in core
- Auth module registers via `ksmbd_register_auth()`
- Core `smb2_sess_setup()` calls registered auth method instead of hard-coded `ksmbd_authenticate()`
- **Kconfig**: `CONFIG_SMB_SERVER_AUTH_NTLM` (tristate, default y)
- **Test**: NTLM authentication with module loaded

#### Step 7: Extract `ksmbd-auth-krb5` (P2, Complexity: M)
- Move SPNEGO/Kerberos code from `auth.c` and `asn1.c` to separate module
- Module registers as auth method with lower priority than NTLM
- **Kconfig**: `CONFIG_SMB_SERVER_AUTH_KRB5` (tristate)
- **Test**: Kerberos authentication with module loaded

#### Step 8: Implement `ksmbd-dfs` (P2, Complexity: L)
- New module implementing DFS referral handling
- Registers FSCTL handlers for `FSCTL_DFS_GET_REFERRALS` and `FSCTL_DFS_GET_REFERRALS_EX`
- Registers path resolution hook for DFS-aware path handling
- **Kconfig**: `CONFIG_SMB_SERVER_DFS` (tristate)

#### Step 9: Implement `ksmbd-vss` (P2, Complexity: L)
- New module implementing VSS/snapshot support
- Registers FSCTL handler for `FSCTL_SRV_ENUMERATE_SNAPSHOTS`
- Registers path resolution hook for @GMT tokens
- Includes pluggable snapshot backends (btrfs, ZFS, LVM)
- **Kconfig**: `CONFIG_SMB_SERVER_VSS` (tristate)

#### Step 10: Implement `ksmbd-audit` (P2, Complexity: M)
- New module implementing audit logging
- Registers AUDIT hook
- Integrates with kernel audit framework
- **Kconfig**: `CONFIG_SMB_SERVER_AUDIT` (tristate)

#### Step 11: Implement `ksmbd-compress` (P3, Complexity: XL)
- New module implementing SMB3 compression
- Registers negotiate context handler
- Registers transform header processor
- Includes compression algorithm registry
- **Kconfig**: `CONFIG_SMB_SERVER_COMPRESS` (tristate)

### 5.2 API Stabilization Order

| Phase | APIs to Stabilize | Milestone |
|-------|-------------------|-----------|
| 1 | Transport ops (`ksmbd_transport_ops`) | Before Step 2 |
| 2 | Extension registry, Hook system | Before Step 4 |
| 3 | FSCTL registration | Before Step 6 |
| 4 | Auth registration | Before Step 6 |
| 5 | Create context registration, Info level registration | Before Step 8 |

### 5.3 Testing Strategy

#### Unit Testing
- Each extracted module must pass all existing xfstests and smbtorture tests
- Module load/unload stress testing (load, use, unload, reload in rapid succession)
- Verify no memory leaks on module unload (`kmemleak`)

#### Integration Testing
- Full client interoperability matrix:
  - Windows 10/11 (SMB 2.1, 3.0, 3.1.1)
  - macOS (with and without Fruit module)
  - Linux smbclient
  - Linux mount.cifs
- Multi-channel with RDMA module loaded/unloaded
- Kerberos authentication with krb5 module loaded/unloaded

#### Performance Testing
- Baseline: monolithic build throughput and latency
- Modular: measure overhead of hook static_key checks (should be < 1ns)
- Modular: measure overhead of FSCTL hash lookup (should be < 100ns)
- Hot path regression test: READ/WRITE throughput must not degrade more than 1%

#### Backward Compatibility Testing
- Monolithic build (all `CONFIG_*` set to `y`): must produce identical binary behavior
- Module build (all `CONFIG_*` set to `m`): must be functionally identical
- Mixed build (some `y`, some `m`): must work correctly

### 5.4 Backward Compatibility: Supporting Both Monolithic and Modular Builds

The Kconfig structure supports three configurations for each optional feature:

```
config SMB_SERVER_FRUIT
    tristate "Apple AAPL extensions support"
    depends on SMB_SERVER
    default n
    help
      Enable Apple AAPL create context extensions for improved
      macOS client compatibility. Can be built as a separate
      module (M) or built into the core (Y).

      If unsure, say N.
```

When `CONFIG_SMB_SERVER_FRUIT=y`:
- `smb2fruit.c` compiles into `ksmbd.ko`
- Registration happens at `ksmbd_server_init()` time (no module load needed)
- Hook invocations use the same mechanism but the static_key is always enabled

When `CONFIG_SMB_SERVER_FRUIT=m`:
- `smb2fruit.c` compiles into `ksmbd-fruit.ko`
- Must be loaded explicitly or via modprobe dependency
- Hooks are registered at module load time

When `CONFIG_SMB_SERVER_FRUIT=n`:
- No fruit code compiled at all
- Hooks for fruit features remain unregistered
- Static keys remain disabled; zero overhead

### 5.5 Updated Makefile Structure

```makefile
# Core module (always built)
obj-$(CONFIG_SMB_SERVER) += ksmbd.o

ksmbd-y := unicode.o auth_core.o vfs.o vfs_cache.o connection.o \
           crypto_ctx.o server.o misc.o oplock.o ksmbd_work.o \
           smbacl.o ndr.o smb2pdu.o smb2ops.o smb2misc.o \
           smb_common.o transport_ipc.o compat.o \
           ksmbd_hooks.o ksmbd_fsctl.o ksmbd_extension.o \
           ksmbd_spnego_negtokeninit.asn1.o \
           ksmbd_spnego_negtokentarg.asn1.o asn1.o \
           mgmt/ksmbd_ida.o mgmt/user_config.o \
           mgmt/share_config.o mgmt/tree_connect.o \
           mgmt/user_session.o

# Legacy SMB1 (bool, compiled into core when enabled)
ksmbd-$(CONFIG_SMB_INSECURE_SERVER) += smb1pdu.o smb1ops.o \
                                        smb1misc.o netmisc.o

# Transport modules
obj-$(CONFIG_SMB_SERVER_TCP)  += ksmbd-transport-tcp.o
ksmbd-transport-tcp-y := transport_tcp.o

obj-$(CONFIG_SMB_SERVER_RDMA) += ksmbd-transport-rdma.o
ksmbd-transport-rdma-y := transport_rdma.o

# Feature modules
obj-$(CONFIG_SMB_SERVER_FRUIT) += ksmbd-fruit.o
ksmbd-fruit-y := smb2fruit.o

obj-$(CONFIG_SMB_SERVER_AUTH_NTLM) += ksmbd-auth-ntlm.o
ksmbd-auth-ntlm-y := auth_ntlm.o

obj-$(CONFIG_SMB_SERVER_AUTH_KRB5) += ksmbd-auth-krb5.o
ksmbd-auth-krb5-y := auth_krb5.o

obj-$(CONFIG_SMB_SERVER_DFS) += ksmbd-dfs.o
ksmbd-dfs-y := dfs.o

obj-$(CONFIG_SMB_SERVER_VSS) += ksmbd-vss.o
ksmbd-vss-y := vss.o

obj-$(CONFIG_SMB_SERVER_AUDIT) += ksmbd-audit.o
ksmbd-audit-y := audit.o

obj-$(CONFIG_SMB_SERVER_COMPRESS) += ksmbd-compress.o
ksmbd-compress-y := compress.o
```

### 5.6 Module Summary Table

| Module | Interface | Performance Impact | Complexity | Dependencies | Priority |
|--------|-----------|-------------------|------------|-------------|----------|
| `ksmbd` (core) | N/A (provides all APIs) | Baseline | N/A | kernel, crypto, NLS | N/A |
| `ksmbd-transport-tcp` | `ksmbd_transport_ops` | Zero | S | Core | P0 |
| `ksmbd-transport-rdma` | `ksmbd_transport_ops` + RDMA extensions | Zero | S | Core, RDMA | P0 |
| `ksmbd-auth-ntlm` | `ksmbd_auth_ops` | 1 indirect call/session setup | M | Core, crypto | P1 |
| `ksmbd-auth-krb5` | `ksmbd_auth_ops` | 1 indirect call/session setup | M | Core, ASN.1 | P2 |
| `ksmbd-fruit` | Hooks + create context handler | 1 static_key check/CREATE | M | Core | P1 |
| `ksmbd-dfs` | `ksmbd_dfs_ops` + FSCTL handler | 1 hash lookup/DFS referral | L | Core | P2 |
| `ksmbd-vss` | `ksmbd_vss_ops` + FSCTL handler | Path resolution per @GMT access | L | Core, FS backend | P2 |
| `ksmbd-compress` | `ksmbd_compress_ops` + algo registry | Per-packet compress/decompress | XL | Core, compression | P3 |
| `ksmbd-acl` | `ksmbd_acl_ops` + CHECK_ACCESS hook | 1 hook call/file open | L | Core | P1 |
| `ksmbd-audit` | AUDIT hook | 1 hook call/operation | M | Core, audit | P2 |

---

## Appendix A: Complete Header File -- `ksmbd_modular.h`

This is the single unified header that extension modules include:

```c
/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KSMBD Modular Extension API
 *
 * This header provides the complete public API for ksmbd extension modules.
 * Extension modules should include ONLY this header (plus standard kernel
 * headers). All internal ksmbd data structures are opaque.
 *
 * ABI Version: 1.0
 */

#ifndef __KSMBD_MODULAR_H__
#define __KSMBD_MODULAR_H__

#include <linux/module.h>
#include <linux/list.h>
#include <linux/types.h>

/* API version -- checked at extension registration */
#define KSMBD_API_VERSION_MAJOR  1
#define KSMBD_API_VERSION_MINOR  0

/* ---- Forward declarations (opaque types) ---- */
struct ksmbd_conn;
struct ksmbd_session;
struct ksmbd_work;
struct ksmbd_file;
struct ksmbd_tree_connect;
struct ksmbd_share_config;
struct ksmbd_transport;
struct ksmbd_crypto_ctx;
struct create_context;
struct smb_ntsd;
struct smb_sid;

/* ---- Extension Registration ---- */

struct ksmbd_extension {
    const char      *name;
    struct module   *owner;
    int             api_version_major;
    int             api_version_minor;
    u64             capabilities;

    int             (*init)(void);
    void            (*exit)(void);
    int             (*conn_init)(struct ksmbd_conn *conn);
    void            (*conn_free)(struct ksmbd_conn *conn);
    int             (*caps_advertise)(struct ksmbd_conn *conn, void *neg_rsp);

    unsigned long   reserved[4];
    struct list_head list;
    int             id;     /* Assigned by core at registration */
};

int ksmbd_register_extension(struct ksmbd_extension *ext);
void ksmbd_unregister_extension(struct ksmbd_extension *ext);

/* Per-connection extension data access */
void *ksmbd_ext_conn_data(struct ksmbd_conn *conn,
                          struct ksmbd_extension *ext);
void ksmbd_ext_set_conn_data(struct ksmbd_conn *conn,
                             struct ksmbd_extension *ext, void *data);

/* ---- Hook System ---- */

enum ksmbd_hook_point {
    KSMBD_HOOK_CONN_ESTABLISHED,
    KSMBD_HOOK_CONN_CLOSING,
    KSMBD_HOOK_PRE_NEGOTIATE,
    KSMBD_HOOK_POST_NEGOTIATE,
    KSMBD_HOOK_PRE_SESSION_SETUP,
    KSMBD_HOOK_POST_SESSION_SETUP,
    KSMBD_HOOK_PRE_TREE_CONNECT,
    KSMBD_HOOK_POST_TREE_CONNECT,
    KSMBD_HOOK_PRE_CREATE,
    KSMBD_HOOK_POST_CREATE,
    KSMBD_HOOK_PRE_CLOSE,
    KSMBD_HOOK_POST_CLOSE,
    KSMBD_HOOK_PRE_READ,
    KSMBD_HOOK_POST_READ,
    KSMBD_HOOK_PRE_WRITE,
    KSMBD_HOOK_POST_WRITE,
    KSMBD_HOOK_PRE_FLUSH,
    KSMBD_HOOK_PRE_QUERY_DIR,
    KSMBD_HOOK_POST_QUERY_DIR,
    KSMBD_HOOK_READDIR_ENTRY,
    KSMBD_HOOK_PRE_QUERY_INFO,
    KSMBD_HOOK_POST_QUERY_INFO,
    KSMBD_HOOK_PRE_SET_INFO,
    KSMBD_HOOK_POST_SET_INFO,
    KSMBD_HOOK_PRE_LOCK,
    KSMBD_HOOK_POST_LOCK,
    KSMBD_HOOK_OPLOCK_BREAK,
    KSMBD_HOOK_PRE_IOCTL,
    KSMBD_HOOK_CHANGE_NOTIFY,
    KSMBD_HOOK_CHECK_ACCESS,
    KSMBD_HOOK_AUDIT,
    __KSMBD_HOOK_MAX,
};

enum ksmbd_hook_verdict {
    KSMBD_HOOK_CONTINUE = 0,
    KSMBD_HOOK_HANDLED  = 1,
    KSMBD_HOOK_ERROR    = -1,
};

struct ksmbd_hook_ctx {
    struct ksmbd_work       *work;
    enum ksmbd_hook_point   point;
    int                     status;
    void                    *data;
    size_t                  data_len;
};

struct ksmbd_hook {
    enum ksmbd_hook_point   point;
    int                     priority;
    struct module           *owner;
    int (*handler)(struct ksmbd_hook_ctx *ctx);
    struct list_head        list;
};

int ksmbd_register_hook(struct ksmbd_hook *hook);
void ksmbd_unregister_hook(struct ksmbd_hook *hook);

/* ---- Transport Registration ---- */

struct ksmbd_transport_ops {
    int  (*read)(struct ksmbd_transport *t, char *buf,
                 unsigned int to_read, int max_retries);
    int  (*writev)(struct ksmbd_transport *t, struct kvec *iov,
                   int nvecs, int size, bool need_invalidate,
                   unsigned int remote_key);
    void (*disconnect)(struct ksmbd_transport *t);
    void (*free_transport)(struct ksmbd_transport *t);
};

struct ksmbd_transport_handler {
    const char      *name;
    struct module   *owner;
    int  (*init)(void);
    void (*stop)(void);
    void (*destroy)(void);
    struct list_head list;
};

int ksmbd_register_transport(struct ksmbd_transport_handler *handler);
void ksmbd_unregister_transport(struct ksmbd_transport_handler *handler);

/* Core functions for transport modules */
struct ksmbd_conn *ksmbd_conn_alloc(void);
void ksmbd_conn_free(struct ksmbd_conn *conn);
int ksmbd_conn_handler_loop(void *p);
bool ksmbd_conn_alive(struct ksmbd_conn *conn);

/* ---- Authentication Registration ---- */

struct ksmbd_auth_ops {
    const char      *name;
    struct module   *owner;
    int             priority;

    int (*negotiate)(struct ksmbd_conn *conn, void *neg_rsp_blob,
                     size_t *blob_len);
    int (*authenticate)(struct ksmbd_conn *conn,
                        struct ksmbd_session *sess,
                        void *in_blob, size_t in_len,
                        void **out_blob, size_t *out_len);
    int (*derive_signing_key)(struct ksmbd_session *sess,
                              struct ksmbd_conn *conn);
    int (*derive_encryption_key)(struct ksmbd_conn *conn,
                                 struct ksmbd_session *sess);
    int (*sign_response)(struct ksmbd_work *work);
    int (*verify_signature)(struct ksmbd_work *work);

    struct list_head list;
};

int ksmbd_register_auth(struct ksmbd_auth_ops *ops);
void ksmbd_unregister_auth(struct ksmbd_auth_ops *ops);

/* ---- FSCTL Registration ---- */

struct ksmbd_fsctl_handler {
    u32             fsctl_code;
    struct module   *owner;
    const char      *name;
    int (*handler)(struct ksmbd_work *work,
                   u64 volatile_fid,
                   const void *in_buf, u32 in_len,
                   void *out_buf, u32 *out_len);
    struct hlist_node hnode;
};

int ksmbd_register_fsctl(struct ksmbd_fsctl_handler *h);
void ksmbd_unregister_fsctl(struct ksmbd_fsctl_handler *h);

/* ---- Create Context Registration ---- */

struct ksmbd_create_ctx_handler {
    char            name[16];
    int             name_len;
    struct module   *owner;
    int (*parse_request)(struct ksmbd_work *work,
                         struct create_context *ctx, void *data);
    int (*build_response)(struct ksmbd_work *work,
                          char *buf, int *len, void *data);
    struct list_head list;
};

int ksmbd_register_create_ctx(struct ksmbd_create_ctx_handler *h);
void ksmbd_unregister_create_ctx(struct ksmbd_create_ctx_handler *h);

/* ---- Info Level Registration ---- */

struct ksmbd_info_handler {
    u8              info_type;
    u8              info_class;
    struct module   *owner;
    int (*query)(struct ksmbd_work *work, struct ksmbd_file *fp,
                 void *buf, int *len);
    int (*set)(struct ksmbd_work *work, struct ksmbd_file *fp,
               const void *buf, int len);
    struct hlist_node hnode;
};

int ksmbd_register_info_handler(struct ksmbd_info_handler *h);
void ksmbd_unregister_info_handler(struct ksmbd_info_handler *h);

/* ---- Work Item Accessors (opaque type access) ---- */

struct ksmbd_conn *ksmbd_work_conn(struct ksmbd_work *work);
struct ksmbd_session *ksmbd_work_sess(struct ksmbd_work *work);
struct ksmbd_tree_connect *ksmbd_work_tcon(struct ksmbd_work *work);
void *ksmbd_work_request_buf(struct ksmbd_work *work);
void *ksmbd_work_response_buf(struct ksmbd_work *work);

/* ---- Connection Accessors ---- */

u16 ksmbd_conn_dialect(struct ksmbd_conn *conn);

/* ---- Crypto Context Pool (for auth modules) ---- */

struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_hmacmd5(void);
struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_hmacsha256(void);
struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_cmacaes(void);
struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_sha256(void);
struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_sha512(void);
struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_md4(void);
struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_md5(void);
struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_gcm(void);
struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_ccm(void);
void ksmbd_release_crypto_ctx(struct ksmbd_crypto_ctx *ctx);

/* ---- Capability Flags ---- */

#define KSMBD_CAP_DFS           BIT(0)
#define KSMBD_CAP_VSS           BIT(1)
#define KSMBD_CAP_FRUIT         BIT(2)
#define KSMBD_CAP_COMPRESS      BIT(3)
#define KSMBD_CAP_ADV_ACL       BIT(4)
#define KSMBD_CAP_AUDIT         BIT(5)

u64 ksmbd_get_loaded_capabilities(void);

/* ---- Debug ---- */

extern int ksmbd_debug_types;
#define KSMBD_DEBUG_SMB     BIT(0)
#define KSMBD_DEBUG_AUTH    BIT(1)
#define KSMBD_DEBUG_VFS     BIT(2)
#define KSMBD_DEBUG_OPLOCK  BIT(3)
#define KSMBD_DEBUG_IPC     BIT(4)
#define KSMBD_DEBUG_CONN    BIT(5)
#define KSMBD_DEBUG_RDMA    BIT(6)

#endif /* __KSMBD_MODULAR_H__ */
```

---

## Appendix B: Kernel Patterns Referenced

| Pattern | Used In | ksmbd Equivalent |
|---------|---------|-----------------|
| `register_filesystem()` / `unregister_filesystem()` | VFS | `ksmbd_register_transport()` |
| `nf_register_net_hook()` with priority chain | netfilter | `ksmbd_register_hook()` with priority |
| `crypto_register_alg()` | Crypto API | `ksmbd_register_compress_algo()` |
| `static_key` for zero-overhead checks | tracepoints | `ksmbd_hook_active[]` |
| `try_module_get()` / `module_put()` | all modular subsystems | Hook invocation |
| RCU-protected list traversal | netfilter, routing | Hook chain traversal |
| ops struct with function pointers | block layer, network | All `*_ops` structs |
| `container_of()` for private data | everywhere | Transport private data |

---

## Appendix C: Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Hook overhead on hot path | READ/WRITE throughput regression | `static_key` bypass when no hooks registered |
| Module reference counting bugs | Use-after-free, crash | `try_module_get()` on every hook invocation; `synchronize_rcu()` on unregister |
| ABI breakage between core and module versions | Module load failure, crash | `KSMBD_API_VERSION_MAJOR` check at registration; `CONFIG_MODVERSIONS` CRC check |
| Extension state leak on connection close | Memory leak | Core calls `conn_free` for all registered extensions during connection teardown |
| Concurrent register/unregister during operation | Race conditions | Mutex for registration; RCU for hook traversal |
| Auth module not loaded | Authentication failure | Core returns `STATUS_LOGON_FAILURE` if no auth module registered |
| Transport module not loaded | Server cannot start | Core returns error on startup if no transport registered |

---

*End of document.*
