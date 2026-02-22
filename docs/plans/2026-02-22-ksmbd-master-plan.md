# KSMBD Master Implementation Plan: Road to Mainline

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task.

**Goal:** Transform ksmbd from a functional but architecturally inconsistent out-of-tree module into a production-grade, modular, extensible, mainline-quality SMB3 server kernel module.

**Architecture:** 8-phase plan covering 145 items across security hardening, memory safety, performance optimization, protocol completeness, modular architecture, and testing infrastructure. Each phase produces a working, buildable, testable module. Dependencies are strictly ordered; independent work units within each phase can be parallelized.

**Tech Stack:** Linux kernel C (6.1-6.12), KUnit, syzkaller, sparse/smatch/coccinelle, GitHub Actions CI, smbtorture

**Source:** `REVIEWFILES/TODO.md` (compiled from 7 review files totaling ~8,500 lines of analysis)

---

## Phase Overview

| Phase | Name | Items | Focus | Depends On |
|-------|------|-------|-------|------------|
| 1 | Security Hardening | 21 | Close exploitable vulnerabilities, crash bugs, DoS vectors | — |
| 2 | Registration Infrastructure | 11 | FSCTL, create context, info-level dispatch tables; config framework | Phase 1 |
| 3 | Critical Missing Features | 18 | CHANGE_NOTIFY, DFS, VSS, reparse points, Fruit completion | Phase 2 |
| 4 | Performance & Concurrency | 14 | Lock contention, buffer pools, zero-copy, slab caches | Phase 1 |
| 5 | Safety & Race Conditions | 12 | UAF, TOCTOU, state machine races, buffer overflows | Phase 1 |
| 6 | Protocol Completeness | 30 | Missing info classes, FSCTLs, signing, encryption, handles | Phases 2-3 |
| 7 | Testing & CI/CD | 8 | KUnit, fuzzing, smbtorture integration, multi-kernel CI | Phases 1-5 |
| 8 | Modular Architecture | 31 | smb2pdu.c decomposition, hook system, module extraction, stable API | Phases 2-6 |

---

## Phase 1: Security Hardening

**Objective:** Close all P0 security, safety, and crash vulnerabilities. After this phase, the module should be safe to expose to untrusted networks.

**Verification:** `make` succeeds, module loads, smbtorture `smb2.connect` passes.

### Task 1.1: Make CAP_NET_ADMIN Unconditional

**Files:**
- Modify: `transport_ipc.c`

**Step 1: Remove the conditional compilation guard**

Find and remove the `#ifdef CONFIG_SMB_SERVER_CHECK_CAP_NET_ADMIN` guard around the genl policy. The `.policy` field in the genl_ops or genl_family must always include `GENL_ADMIN_PERM` so that only privileged processes can inject netlink messages.

```c
/* BEFORE: */
#ifdef CONFIG_SMB_SERVER_CHECK_CAP_NET_ADMIN
	.policy = ...,
#endif

/* AFTER: always require CAP_NET_ADMIN */
	.policy = ...,
```

Also remove the `CONFIG_SMB_SERVER_CHECK_CAP_NET_ADMIN` option from `Kconfig`.

**Step 2: Build and verify**

Run: `make clean && make`
Expected: Builds without errors

**Step 3: Commit**

```bash
git add transport_ipc.c Kconfig
git commit -m "security: make CAP_NET_ADMIN check unconditional

Remove CONFIG_SMB_SERVER_CHECK_CAP_NET_ADMIN guard. Without it,
any unprivileged process with netlink access can inject IPC
responses to the kernel module. [CRITICAL-01]"
```

---

### Task 1.2: Fix IOCTL InputOffset Bounds + EA Set Loop

**Files:**
- Modify: `smb2pdu.c`

**Step 1: Add InputOffset bounds validation in smb2_ioctl()**

Before using `le32_to_cpu(req->InputOffset)` as a pointer offset, validate:
```c
unsigned int input_offset = le32_to_cpu(req->InputOffset);
unsigned int input_count = le32_to_cpu(req->InputCount);

if (input_count > 0) {
    if (input_offset < offsetof(struct smb2_ioctl_req, Buffer) ||
        input_offset + input_count > get_rfc1002_len(work->request_buf) + 4) {
        pr_err_ratelimited("Invalid IOCTL input offset/count\n");
        rc = -EINVAL;
        goto out;
    }
}
```

**Step 2: Fix EA set loop to validate NextEntryOffset**

In the EA set iteration loop, validate that `NextEntryOffset` doesn't exceed remaining buffer:
```c
unsigned int remaining = total_ea_len - offset;
if (le32_to_cpu(ea->NextEntryOffset) > remaining) {
    pr_err_ratelimited("EA NextEntryOffset exceeds buffer\n");
    rc = -EINVAL;
    break;
}
```

**Step 3: Build and verify**

Run: `make`
Expected: Builds without errors

**Step 4: Commit**

```bash
git add smb2pdu.c
git commit -m "security: validate IOCTL InputOffset and EA loop bounds

Add bounds checking for InputOffset/InputCount in smb2_ioctl()
before pointer arithmetic. Fix EA set loop to validate
NextEntryOffset stays within buffer. [CRITICAL-06, CRITICAL-07]"
```

---

### Task 1.3: Replace ssleep(5) with Non-Blocking Delay

**Files:**
- Modify: `auth.c`

**Step 1: Replace ssleep with delayed connection close or async backoff**

Find the `ssleep(5)` call in the authentication failure path. Replace with a connection-level backoff counter:
```c
/* BEFORE: */
ssleep(5);

/* AFTER: use a non-blocking delay */
conn->auth_failures++;
if (conn->auth_failures >= KSMBD_AUTH_MAX_FAILURES) {
    pr_info_ratelimited("Too many auth failures from %pIS\n",
                        KSMBD_TCP_PEER_SOCKADDR(conn));
    set_conn_state(conn, CONN_STATE_NEED_RECONNECT);
}
```

This avoids blocking a kernel worker thread for 5 seconds per failure.

**Step 2: Build and verify**

Run: `make`

**Step 3: Commit**

```bash
git add auth.c
git commit -m "security: replace ssleep(5) with non-blocking auth backoff

ssleep(5) in auth failure path blocks a kernel worker thread,
enabling trivial DoS. Replace with connection-level failure
counter and disconnect after threshold. [CRITICAL-05, C-01]"
```

---

### Task 1.4: Add Per-IP Connection Rate Limiting

**Files:**
- Modify: `connection.c`, `connection.h`, `transport_tcp.c`

**Step 1: Add per-IP tracking structure**

Add a hash table tracking connection count per IP:
```c
#define KSMBD_MAX_CONNECTIONS_PER_IP  64
#define KSMBD_MAX_TOTAL_CONNECTIONS   1024

struct ksmbd_conn_counter {
    struct hlist_node node;
    struct sockaddr_storage addr;
    atomic_t count;
};
```

**Step 2: Check limits before accepting connections**

In the TCP connection accept path, check the per-IP count:
```c
if (atomic_read(&conn_counter->count) >= KSMBD_MAX_CONNECTIONS_PER_IP) {
    pr_info_ratelimited("Connection limit reached for %pIS\n", addr);
    kernel_sock_shutdown(newsock, SHUT_RDWR);
    sock_release(newsock);
    continue;
}
```

**Step 3: Track total connection count with atomic**

```c
static atomic_t ksmbd_total_connections = ATOMIC_INIT(0);
```

**Step 4: Build and verify**

Run: `make`

**Step 5: Commit**

```bash
git add connection.c connection.h transport_tcp.c
git commit -m "security: add per-IP connection rate limiting

Each connection allocates kernel memory. Without limits,
thousands of pre-auth connections cause OOM. Add per-IP
limit (64) and total limit (1024). [CRITICAL-04, DoS-01]"
```

---

### Task 1.5: Fix NDR Unaligned Access

**Files:**
- Modify: `ndr.c`

**Step 1: Replace direct struct member access with get_unaligned_le*()**

Find all places in `ndr.c` that cast wire data to structs and access members directly. Replace with `get_unaligned_le32()`, `get_unaligned_le16()`, etc.:

```c
/* BEFORE: */
val = *((__le32 *)data);

/* AFTER: */
val = get_unaligned_le32(data);
```

**Step 2: Add NDR string length bounds checking**

Clamp string lengths read from NDR data against remaining buffer:
```c
if (str_len > remaining_len) {
    pr_err_ratelimited("NDR string length exceeds buffer\n");
    return -EINVAL;
}
```

**Step 3: Build and verify (especially on ARM if available)**

Run: `make`

**Step 4: Commit**

```bash
git add ndr.c
git commit -m "safety: fix NDR unaligned access and string length validation

Use get_unaligned_le*() for all wire data access in NDR
encode/decode. Crashes on ARM/strict-alignment architectures.
Add bounds checking for NDR string lengths. [M-01, MEDIUM-01]"
```

---

### Task 1.6: Fix NULL Crypto Context + Crypto Livelock

**Files:**
- Modify: `crypto_ctx.c`, `crypto_ctx.h`

**Step 1: Add NULL check after ksmbd_find_crypto_ctx()**

All callers of `ksmbd_find_crypto_ctx()` must check for NULL return:
```c
ctx = ksmbd_find_crypto_ctx();
if (!ctx)
    return -ENOMEM;
```

**Step 2: Add backoff and failure limit to crypto context allocation**

Replace infinite retry loop with bounded retry + exponential backoff:
```c
#define KSMBD_CRYPTO_CTX_MAX_RETRIES 5

for (retries = 0; retries < KSMBD_CRYPTO_CTX_MAX_RETRIES; retries++) {
    ctx = try_find_crypto_ctx();
    if (ctx)
        return ctx;
    usleep_range(100 << retries, 200 << retries);
}
return NULL;  /* Caller handles failure */
```

**Step 3: Build and verify**

Run: `make`

**Step 4: Commit**

```bash
git add crypto_ctx.c crypto_ctx.h
git commit -m "safety: fix NULL crypto context deref and livelock

ksmbd_find_crypto_ctx() can return NULL if pool exhausted.
Callers didn't check. Also, allocation retried indefinitely
causing livelock. Add bounded retry with backoff. [M-02, F-02]"
```

---

### Task 1.7: Fix Session Binding UAF + EA Heap Overflow

**Files:**
- Modify: `smb2pdu.c`

**Step 1: Fix session binding race**

In `smb2_sess_setup()`, hold the connection lock across the session lookup and binding operation to prevent concurrent destruction:
```c
down_write(&conn->session_lock);
sess = ksmbd_session_lookup(conn, sess_id);
if (!sess) {
    up_write(&conn->session_lock);
    /* handle error */
}
/* ... binding logic ... */
up_write(&conn->session_lock);
```

**Step 2: Fix EA buffer size validation**

Before parsing EA data, validate the total size matches the buffer:
```c
if (le32_to_cpu(req->BufferLength) < sizeof(struct smb2_ea_info)) {
    rc = -EINVAL;
    goto out;
}
```

**Step 3: Build and verify**

Run: `make`

**Step 4: Commit**

```bash
git add smb2pdu.c
git commit -m "safety: fix session binding UAF and EA buffer validation

Hold session_lock across lookup+bind to prevent concurrent
destruction (UAF). Validate EA buffer size before parsing
to prevent heap overflow. [M-03, M-04]"
```

---

### Task 1.8: Replace atomic_t with refcount_t

**Files:**
- Modify: `connection.h`, `mgmt/share_config.h`, `mgmt/tree_connect.h`, `oplock.h`, `vfs_cache.h`
- Modify: All `.c` files that use `atomic_inc/dec/read` on refcounts

**Step 1: Mechanical replacement**

For each refcount field:
```c
/* BEFORE: */
atomic_t refcount;
atomic_set(&obj->refcount, 1);
atomic_inc(&obj->refcount);
if (atomic_dec_and_test(&obj->refcount))

/* AFTER: */
refcount_t refcount;
refcount_set(&obj->refcount, 1);
refcount_inc(&obj->refcount);
if (refcount_dec_and_test(&obj->refcount))
```

Affected structs: `ksmbd_conn`, `ksmbd_session`, `ksmbd_share_config`, `ksmbd_tree_connect`, `oplock_info`, `ksmbd_file`.

**Step 2: Build and verify**

Run: `make`

**Step 3: Commit**

```bash
git add connection.h mgmt/ oplock.h vfs_cache.h *.c
git commit -m "safety: replace atomic_t refcounting with refcount_t

refcount_t provides saturation-based overflow protection.
atomic_t silently wraps on overflow, enabling use-after-free.
Drop-in replacement across all refcounted objects. [P0-2]"
```

---

### Task 1.9: Add CONFIG_KSMBD_FRUIT to Kconfig

**Files:**
- Modify: `Kconfig`
- Modify: `Makefile` (remove the `?= n` default)

**Step 1: Add Kconfig entry**

```
config KSMBD_FRUIT
	bool "Apple macOS (Fruit) extensions"
	depends on SMB_SERVER
	default n
	help
	  Enable Apple SMB extensions for macOS compatibility.
	  Provides support for AAPL create context negotiation,
	  Time Machine backups, Finder metadata, and resource forks.

	  If unsure, say N.
```

**Step 2: Update Makefile**

Remove the standalone `CONFIG_KSMBD_FRUIT ?= n` line. Let Kconfig handle it:
```makefile
ksmbd-$(CONFIG_KSMBD_FRUIT) += smb2fruit.o
```

**Step 3: Build and verify with both settings**

Run: `make` (default: disabled)
Run: `make CONFIG_KSMBD_FRUIT=y` (enabled)

**Step 4: Commit**

```bash
git add Kconfig Makefile
git commit -m "build: add CONFIG_KSMBD_FRUIT to Kconfig

Move fruit toggle from Makefile-only (invisible to menuconfig)
to proper Kconfig entry with help text. [P0-1]"
```

---

### Task 1.10: Validate Remaining P0 Security Items

**Files:**
- Modify: `smb2pdu.c` (SetInfo buffer validation, lock count validation, POSIX context validation)
- Modify: `transport_rdma.c` (RDMA buffer descriptor validation)
- Modify: `misc.c` (get_nlink underflow)

**Step 1: Validate SetInfo buffer sizes (HIGH-06)**

In each `smb2_set_info_*` handler, verify that the input buffer is large enough for the expected structure before accessing fields.

**Step 2: Cap lock count (HIGH-09)**

In `smb2_lock()`:
```c
#define KSMBD_MAX_LOCK_COUNT 64
if (le16_to_cpu(req->LockCount) > KSMBD_MAX_LOCK_COUNT) {
    rc = -EINVAL;
    goto out;
}
```

**Step 3: Fix get_nlink underflow (LOW-05)**

```c
if (S_ISDIR(st->mode))
    nlink = max_t(int, nlink - 1, 0);
```

**Step 4: Rate-limit network-triggered pr_err (LOW-02, LOW-06)**

Replace `pr_err(...)` with `pr_err_ratelimited(...)` for all error messages triggered by client input.

**Step 5: Build and verify**

Run: `make`

**Step 6: Commit**

```bash
git add smb2pdu.c transport_rdma.c misc.c
git commit -m "security: validate wire-format sizes, cap lock count, fix nlink

Validate SetInfo buffer sizes before access. Cap LockCount
at 64 to prevent memory exhaustion. Fix nlink underflow for
directories. Rate-limit client-triggered error messages.
[HIGH-06, HIGH-09, LOW-02, LOW-05, LOW-06]"
```

---

## Phase 2: Registration Infrastructure

**Objective:** Build the dispatch tables and configuration framework that all feature work depends on. This is the architectural foundation.

**Depends on:** Phase 1 complete (security hardened)

**Verification:** `make` succeeds, existing smbtorture tests pass, new registration APIs have KUnit tests.

### Task 2.1: FSCTL Handler Registration Table

**Files:**
- Create: `ksmbd_fsctl.c`
- Create: `ksmbd_fsctl.h`
- Modify: `smb2pdu.c` (replace switch-case dispatch with hash lookup)
- Modify: `Makefile`

**Step 1: Define the registration API**

```c
/* ksmbd_fsctl.h */
#ifndef __KSMBD_FSCTL_H
#define __KSMBD_FSCTL_H

#include <linux/types.h>
#include <linux/hashtable.h>

struct ksmbd_work;

struct ksmbd_fsctl_handler {
    __le32 ctl_code;
    int (*handler)(struct ksmbd_work *work,
                   u64 id, void *in_buf,
                   unsigned int in_buf_len,
                   unsigned int max_out_len,
                   void *out_buf,
                   unsigned int *out_len);
    struct module *owner;
    struct hlist_node node;
    struct rcu_head rcu;
};

int ksmbd_register_fsctl(struct ksmbd_fsctl_handler *h);
void ksmbd_unregister_fsctl(struct ksmbd_fsctl_handler *h);
int ksmbd_dispatch_fsctl(struct ksmbd_work *work, __le32 ctl_code,
                         u64 id, void *in_buf, unsigned int in_buf_len,
                         unsigned int max_out_len, void *out_buf,
                         unsigned int *out_len);
int ksmbd_fsctl_init(void);
void ksmbd_fsctl_exit(void);

#endif
```

**Step 2: Implement the hash table dispatch**

```c
/* ksmbd_fsctl.c */
#define FSCTL_HASH_BITS 8
static DEFINE_HASHTABLE(fsctl_handlers, FSCTL_HASH_BITS);
static DEFINE_SPINLOCK(fsctl_lock);

int ksmbd_register_fsctl(struct ksmbd_fsctl_handler *h)
{
    spin_lock(&fsctl_lock);
    hash_add_rcu(fsctl_handlers, &h->node,
                 le32_to_cpu(h->ctl_code));
    spin_unlock(&fsctl_lock);
    return 0;
}

void ksmbd_unregister_fsctl(struct ksmbd_fsctl_handler *h)
{
    spin_lock(&fsctl_lock);
    hash_del_rcu(&h->node);
    spin_unlock(&fsctl_lock);
    synchronize_rcu();
}

int ksmbd_dispatch_fsctl(struct ksmbd_work *work, __le32 ctl_code,
                         u64 id, void *in_buf, unsigned int in_buf_len,
                         unsigned int max_out_len, void *out_buf,
                         unsigned int *out_len)
{
    struct ksmbd_fsctl_handler *h;
    u32 code = le32_to_cpu(ctl_code);
    int ret = -EOPNOTSUPP;

    rcu_read_lock();
    hash_for_each_possible_rcu(fsctl_handlers, h, node, code) {
        if (le32_to_cpu(h->ctl_code) == code &&
            try_module_get(h->owner)) {
            rcu_read_unlock();
            ret = h->handler(work, id, in_buf, in_buf_len,
                             max_out_len, out_buf, out_len);
            module_put(h->owner);
            return ret;
        }
    }
    rcu_read_unlock();
    return ret;
}
```

**Step 3: Register existing FSCTL handlers**

Move each case from the `smb2_ioctl()` switch into a static `ksmbd_fsctl_handler` and register them in `ksmbd_fsctl_init()`.

**Step 4: Modify smb2_ioctl() to use dispatch**

```c
ret = ksmbd_dispatch_fsctl(work, req->CtlCode, id,
                           in_buf, in_buf_len,
                           max_out_len, out_buf, &out_len);
if (ret == -EOPNOTSUPP) {
    /* fallback: log unsupported FSCTL */
    pr_debug("Unsupported FSCTL 0x%x\n", le32_to_cpu(req->CtlCode));
}
```

**Step 5: Add to Makefile**

```makefile
ksmbd-y += ksmbd_fsctl.o
```

**Step 6: Build and verify**

Run: `make`
Verify: Existing smbtorture IOCTL tests still pass.

**Step 7: Commit**

```bash
git add ksmbd_fsctl.c ksmbd_fsctl.h smb2pdu.c Makefile
git commit -m "arch: add FSCTL handler registration table

Replace hardcoded switch-case dispatch in smb2_ioctl() with
RCU-protected hash table lookup. All existing FSCTLs registered
as static handlers. New FSCTLs can be added via modules.
[P1-1, FSCTL dispatch extensibility]"
```

---

### Task 2.2: Create Context Handler Registration

**Files:**
- Create: `ksmbd_create_ctx.c`
- Create: `ksmbd_create_ctx.h`
- Modify: `smb2pdu.c` (extract inline context processing from `smb2_open()`)
- Modify: `Makefile`

**Step 1: Define registration API**

```c
/* ksmbd_create_ctx.h */
struct ksmbd_create_context_handler {
    const char *tag;
    size_t tag_len;  /* 4 or 16 */
    int (*on_request)(struct ksmbd_work *work,
                      struct ksmbd_file *fp,
                      const void *ctx_data,
                      unsigned int ctx_len);
    int (*on_response)(struct ksmbd_work *work,
                       struct ksmbd_file *fp,
                       void *rsp_buf,
                       unsigned int *rsp_len);
    struct module *owner;
    struct list_head list;
    struct rcu_head rcu;
};

int ksmbd_register_create_context(struct ksmbd_create_context_handler *h);
void ksmbd_unregister_create_context(struct ksmbd_create_context_handler *h);
```

**Step 2: Implement registration and dispatch**

Use an RCU-protected linked list (create contexts are few enough that hash table is overkill).

**Step 3: Extract existing inline context processing from smb2_open()**

Move each context handler (DHnQ, DHnC, DH2Q, DH2C, AlSi, MxAc, TWrp, QFid, RqLs, ExtA, SecD, POSIX, AAPL) into registered handlers.

**Step 4: Build, verify, commit**

---

### Task 2.3: Unified Configuration Framework

**Files:**
- Create: `ksmbd_config.c`
- Create: `ksmbd_config.h`
- Modify: `server.h` (use config framework instead of raw globals)
- Modify: `Makefile`

**Step 1: Define parameter registry**

```c
enum ksmbd_config_param {
    KSMBD_CFG_MAX_READ_SIZE,
    KSMBD_CFG_MAX_WRITE_SIZE,
    KSMBD_CFG_MAX_TRANS_SIZE,
    KSMBD_CFG_MAX_CREDITS,
    KSMBD_CFG_MAX_CONNECTIONS,
    KSMBD_CFG_MAX_CONNECTIONS_PER_IP,
    KSMBD_CFG_DEADTIME,
    KSMBD_CFG_COPY_CHUNK_MAX_COUNT,
    KSMBD_CFG_COPY_CHUNK_MAX_SIZE,
    KSMBD_CFG_SMB_ECHO_INTERVAL,
    KSMBD_CFG_IPC_TIMEOUT,
    __KSMBD_CFG_MAX,
};
```

Each parameter has: name, type, default, min, max, runtime-changeable flag.

**Step 2: Populate from netlink startup request with validation**

Replace raw assignment with validated `ksmbd_config_set_*()` calls.

**Step 3: Replace hardcoded functions**

```c
/* BEFORE: */
unsigned int ksmbd_server_side_copy_max_chunk_count(void) { return 256; }

/* AFTER: */
unsigned int ksmbd_server_side_copy_max_chunk_count(void)
{
    u32 val;
    ksmbd_config_get_u32(KSMBD_CFG_COPY_CHUNK_MAX_COUNT, &val);
    return val;
}
```

**Step 4: Build, verify, commit**

---

### Task 2.4: Info-Level Handler Registration Table

**Files:**
- Create: `ksmbd_info.c`
- Create: `ksmbd_info.h`
- Modify: `smb2pdu.c` (refactor `smb2_get_info_file()`, `smb2_set_info_file()`, `smb2_get_info_filesystem()`)
- Modify: `Makefile`

Same pattern as FSCTL registration but keyed on `(info_type, info_class)` tuple.

**Step 1: Define API**

```c
struct ksmbd_info_handler {
    u8 info_type;
    u8 info_class;
    int (*get)(struct ksmbd_work *work, struct ksmbd_file *fp,
               void *rsp_buf, unsigned int max_len,
               unsigned int *out_len);
    int (*set)(struct ksmbd_work *work, struct ksmbd_file *fp,
               const void *buf, unsigned int len);
    struct hlist_node node;
};
```

**Step 2: Register existing handlers, modify dispatch**

**Step 3: Build, verify, commit**

---

### Task 2.5: Debugfs Interface

**Files:**
- Create: `ksmbd_debugfs.c`
- Modify: `server.c` (init/cleanup calls)
- Modify: `Makefile`

**Step 1: Create debugfs entries**

```
/sys/kernel/debug/ksmbd/
    connections    # Per-connection state dump
    sessions       # Active session listing
    oplocks        # Oplock/lease table
    credits        # Credit balance per connection
    stats          # Request/response counters
    config         # Current configuration dump
```

**Step 2: Implement seq_file handlers for each entry**

**Step 3: Build, verify, commit**

---

### Task 2.6: Three-Tier Feature Negotiation

**Files:**
- Modify: `smb_common.h` (feature flags)
- Modify: `connection.h` (per-connection feature state)
- Modify: `server.h` (global feature state)
- Modify: `ksmbd_config.c` (feature enable/disable)

**Step 1: Define feature flag enum**

```c
enum ksmbd_feature {
    KSMBD_FEAT_LEASING,
    KSMBD_FEAT_MULTICHANNEL,
    KSMBD_FEAT_ENCRYPTION,
    KSMBD_FEAT_DURABLE_HANDLE,
    KSMBD_FEAT_FRUIT,
    KSMBD_FEAT_DFS,
    KSMBD_FEAT_VSS,
    KSMBD_FEAT_COMPRESSION,
    __KSMBD_FEAT_MAX,
};
```

**Step 2: Three-tier check**

```c
static inline bool ksmbd_feature_enabled(struct ksmbd_conn *conn,
                                          enum ksmbd_feature feat)
{
    /* Tier 1: compiled in? */
    if (!IS_ENABLED(ksmbd_feature_config[feat]))
        return false;
    /* Tier 2: globally enabled? */
    if (!test_bit(feat, &server_conf.features))
        return false;
    /* Tier 3: per-connection negotiated? */
    return test_bit(feat, &conn->features);
}
```

**Step 3: Replace existing flag checks throughout codebase**

**Step 4: Build, verify, commit**

---

## Phase 3: Critical Missing Features

**Objective:** Implement the features that break basic interoperability (CHANGE_NOTIFY) and enterprise deployment (DFS, VSS, reparse points).

**Depends on:** Phase 2 (registration infrastructure)

**Verification:** Windows Explorer auto-refresh works, Previous Versions tab populated, DFS referral lookup succeeds, symlinks work.

### Task 3.1: Implement CHANGE_NOTIFY

**Files:**
- Create: `ksmbd_notify.c`
- Create: `ksmbd_notify.h`
- Modify: `smb2pdu.c` (replace stub with real handler)
- Modify: `vfs_cache.c` (add inotify watch management)
- Modify: `Makefile`

**Step 1: Design the notification subsystem**

```c
struct ksmbd_notify_watch {
    struct ksmbd_file *fp;
    struct ksmbd_work *pending_work; /* async work waiting for event */
    u32 completion_filter;
    bool watch_tree;
    struct list_head list;
    int inotify_wd;  /* inotify watch descriptor */
};
```

**Step 2: Integrate with Linux inotify**

Use `inotify_init1()` in kernel space (via internal APIs) or `fsnotify` for directory watching.

**Step 3: Map inotify events to SMB2 FILE_NOTIFY_CHANGE_* flags**

```c
static u32 inotify_to_smb2_filter(u32 mask)
{
    u32 filter = 0;
    if (mask & IN_CREATE)     filter |= FILE_NOTIFY_CHANGE_FILE_NAME;
    if (mask & IN_DELETE)     filter |= FILE_NOTIFY_CHANGE_FILE_NAME;
    if (mask & IN_MODIFY)     filter |= FILE_NOTIFY_CHANGE_LAST_WRITE;
    if (mask & IN_ATTRIB)     filter |= FILE_NOTIFY_CHANGE_ATTRIBUTES;
    if (mask & IN_MOVED_FROM) filter |= FILE_NOTIFY_CHANGE_FILE_NAME;
    if (mask & IN_MOVED_TO)   filter |= FILE_NOTIFY_CHANGE_FILE_NAME;
    /* ... */
    return filter;
}
```

**Step 4: Implement async response mechanism**

Reuse the existing async framework from LOCK:
```c
int smb2_notify(struct ksmbd_work *work)
{
    /* ... setup watch ... */
    /* Queue the work as pending async */
    work->async_id = ksmbd_acquire_async_msg_id(&conn->async_ids);
    /* ... install inotify watch ... */
    /* Return STATUS_PENDING */
}
```

**Step 5: Handle CANCEL for pending notify requests**

**Step 6: Handle buffer overflow (STATUS_NOTIFY_ENUM_DIR)**

**Step 7: Build, verify with Windows Explorer**

**Step 8: Commit**

---

### Task 3.2: Implement DFS Referrals

**Files:**
- Create: `ksmbd_dfs.c`
- Create: `ksmbd_dfs.h`
- Modify: `ksmbd_netlink.h` (add DFS referral message types)
- Modify: `transport_ipc.c` (add DFS referral IPC handler)
- Modify: `smb2pdu.c` (advertise SMB2_GLOBAL_CAP_DFS, handle DFS flags)
- Modify: `Makefile`

**Step 1: Register FSCTL handlers via the new registration API**

```c
static struct ksmbd_fsctl_handler dfs_referrals_handler = {
    .ctl_code = cpu_to_le32(FSCTL_DFS_GET_REFERRALS),
    .handler = ksmbd_dfs_get_referrals,
    .owner = THIS_MODULE,
};
```

**Step 2: Implement referral lookup via IPC to ksmbd.mountd**

**Step 3: Handle SMB2_FLAGS_DFS_OPERATIONS in request processing**

**Step 4: Advertise SMB2_GLOBAL_CAP_DFS in negotiate response**

**Step 5: Build, verify, commit**

---

### Task 3.3: Implement VSS/Snapshots

**Files:**
- Create: `ksmbd_vss.c`
- Create: `ksmbd_vss.h`
- Modify: `smb2pdu.c` (TIMEWARP context, snapshot enumeration)
- Modify: `Makefile`

**Step 1: Register FSCTL_SRV_ENUMERATE_SNAPSHOTS handler**

**Step 2: Implement snapshot enumeration with backend abstraction**

```c
struct ksmbd_snapshot_backend {
    const char *name;
    int (*enumerate)(const char *share_path,
                     struct ksmbd_snapshot_list *list);
    int (*resolve_path)(const char *share_path,
                        const char *gmt_token,
                        char *resolved, size_t len);
};
```

Backends: btrfs (`.snapshots/`), ZFS (`.zfs/snapshot/`), LVM.

**Step 3: Implement TIMEWARP create context handler**

Parse `@GMT-YYYY.MM.DD-HH.MM.SS` token, resolve to snapshot path, open file from snapshot.

**Step 4: Build, verify with Windows "Previous Versions" tab**

**Step 5: Commit**

---

### Task 3.4: Implement Reparse Points

**Files:**
- Modify: `smb2pdu.c` or register via FSCTL table

**Step 1: Implement FSCTL_SET_REPARSE_POINT**

Parse reparse data buffer, create symlink/junction via VFS.

**Step 2: Implement FSCTL_DELETE_REPARSE_POINT**

**Step 3: Complete FSCTL_GET_REPARSE_POINT (return full data buffer)**

**Step 4: Build, verify with Windows symlinks**

**Step 5: Commit**

---

### Task 3.5: Complete Fruit Module Gaps

**Files:**
- Modify: `smb2fruit.c`
- Modify: `smb2pdu.c`

**Step 1: Wire AFP_AfpInfo stream interception into named stream open**

**Step 2: Implement Time Machine quota enforcement**

**Step 3: Complete ReadDirAttr enrichment (rfork size, max access)**

**Step 4: Wire resolve_fileid into AAPL volume capabilities**

**Step 5: Build, verify with macOS Finder**

**Step 6: Commit**

---

### Task 3.6: Implement FILE_NAME_INFORMATION + Missing Info Classes

**Files:**
- Modify: `smb2pdu.c` (or register via info-level table)

**Step 1: Add FILE_NAME_INFORMATION (class 9) query handler**

**Step 2: Add FS_CONTROL_INFORMATION set handler**

**Step 3: Build, verify, commit**

---

## Phase 4: Performance & Concurrency

**Objective:** Eliminate lock contention hotspots, reduce per-request allocation overhead, enable zero-copy I/O.

**Depends on:** Phase 1 (refcount_t, basic safety)

**Verification:** smbtorture `smb2.rw` passes, throughput measurements show improvement.

### Task 4.1: Per-Bucket Inode Hash Locking

**Files:**
- Modify: `vfs_cache.c`

Replace single global `inode_hash_lock` with per-bucket spinlocks:
```c
struct inode_hash_bucket {
    struct hlist_head head;
    spinlock_t lock;
};
static struct inode_hash_bucket inode_hash[1 << INODE_HASH_BITS];
```

---

### Task 4.2: Per-Bucket Connection Hash Locking

**Files:**
- Modify: `connection.c`

Same pattern as inode hash. Replace global connection list lock with per-bucket locks.

---

### Task 4.3: Per-File Lease Locking

**Files:**
- Modify: `oplock.c`

Replace global `lease_list_lock` with per-inode-info locking. Each `ksmbd_inode` already has a lock — use it for lease operations on that file.

---

### Task 4.4: Dedicated Slab Caches

**Files:**
- Modify: `ksmbd_work.c`, `server.c`, `oplock.c`, `vfs_cache.c`

```c
static struct kmem_cache *ksmbd_work_cache;
static struct kmem_cache *ksmbd_fp_cache;
static struct kmem_cache *ksmbd_opinfo_cache;

/* In server_init(): */
ksmbd_work_cache = kmem_cache_create("ksmbd_work",
    sizeof(struct ksmbd_work), 0,
    SLAB_HWCACHE_ALIGN | SLAB_ACCOUNT, NULL);
```

---

### Task 4.5: READ/WRITE Buffer Pool

**Files:**
- Create: `ksmbd_buffer.c`
- Create: `ksmbd_buffer.h`
- Modify: `smb2pdu.c`

Replace per-request `kvzalloc()` with a pool of pre-allocated buffers:
```c
struct ksmbd_buffer_pool {
    struct list_head free_list;
    spinlock_t lock;
    unsigned int buf_size;
    unsigned int total;
    unsigned int free;
};
```

---

### Task 4.6: Zero-Copy I/O Path

**Files:**
- Modify: `smb2pdu.c` (smb2_read)
- Modify: `vfs.c`

Use `kernel_sendfile()` or `splice` to send file data directly to the socket without copying through an intermediate kernel buffer.

---

### Task 4.7: RCU for Read-Heavy Data Structures

**Files:**
- Modify: `mgmt/share_config.c` (share config lookup)
- Modify: `mgmt/user_session.c` (session lookup)

Replace rwlock-protected lookups with RCU:
```c
/* Reader: */
rcu_read_lock();
share = ksmbd_share_config_get_rcu(name);
rcu_read_unlock();

/* Writer: */
spin_lock(&share_config_lock);
/* ... update ... */
spin_unlock(&share_config_lock);
synchronize_rcu();
```

---

## Phase 5: Safety & Race Conditions

**Objective:** Fix all identified race conditions, TOCTOU vulnerabilities, and buffer overflow risks.

**Depends on:** Phase 1 (refcount_t)

### Task 5.1: Fix TOCTOU in Path Resolution

**Files:**
- Modify: `vfs.c`

Use `LOOKUP_BENEATH` flag for all path lookups to prevent escaping the share root:
```c
err = kern_path(path, LOOKUP_FOLLOW | LOOKUP_BENEATH, &kpath);
```

Add post-open path verification:
```c
/* Verify opened file is within share root */
if (!path_is_under(&file->f_path, &share_root_path)) {
    fput(file);
    return -EACCES;
}
```

---

### Task 5.2: Fix Session State Machine Races

**Files:**
- Modify: `smb2pdu.c`, `server.c`

Protect all session state transitions with the session lock:
```c
down_write(&sess->state_lock);
if (sess->state != SMB2_SESSION_IN_PROGRESS) {
    up_write(&sess->state_lock);
    return -EINVAL;
}
sess->state = SMB2_SESSION_VALID;
up_write(&sess->state_lock);
```

---

### Task 5.3: Fix Durable Handle Scavenger Race

**Files:**
- Modify: `vfs_cache.c`, `smb2pdu.c`

Hold a reference on the handle during scavenger processing. Check reference count before freeing:
```c
if (refcount_dec_and_test(&fp->refcount)) {
    /* Safe to free — no concurrent reconnect */
    ksmbd_close_fd(work, fp->volatile_id);
}
```

---

### Task 5.4: Fix Lock Rollback UAF

**Files:**
- Modify: `smb2pdu.c`

In `smb2_lock()`, ensure lock rollback doesn't free locks still referenced by waiting threads. Use the file lock list lock properly.

---

### Task 5.5: Fix Buffer Overflow in Security Descriptor Construction

**Files:**
- Modify: `smbacl.c`

Validate total security descriptor size against output buffer before writing:
```c
if (sd_len > max_rsp_len) {
    *pntsd = NULL;
    return -ENOSPC;
}
```

---

### Task 5.6: Constant-Time Auth Comparison + Key Scrubbing

**Files:**
- Modify: `auth.c`

```c
/* BEFORE: */
if (memcmp(received_hash, computed_hash, CIFS_HMAC_MD5_HASH_SIZE))

/* AFTER: */
if (crypto_memneq(received_hash, computed_hash, CIFS_HMAC_MD5_HASH_SIZE))
```

Add `memzero_explicit()` in every error path that handles session keys.

---

## Phase 6: Protocol Completeness

**Objective:** Implement remaining info classes, FSCTLs, signing algorithms, and handle types for full MS-SMB2 compliance.

**Depends on:** Phases 2-3 (registration infrastructure + critical features)

### Task 6.1: AES-GMAC Signing

Implement `SIGNING_ALG_AES_GMAC` negotiation and signing:
- Modify: `smb2pdu.c` (negotiate context handling)
- Modify: `auth.c` (GMAC signing/verification)
- Modify: `smb2ops.c` (ops table for SMB 3.1.1)

### Task 6.2: APP_INSTANCE_ID / APP_INSTANCE_VERSION Create Contexts

Register via create context handler API:
- Modify: `smb2pdu.c` (or register via `ksmbd_create_ctx`)

### Task 6.3: Resilient Handles

Implement `FSCTL_LMR_REQUEST_RESILIENCY`:
- Register via FSCTL handler API

### Task 6.4: Quota Support

Implement `SMB2_O_INFO_QUOTA`, `FILE_QUOTA_INFORMATION`:
- Register via info-level handler API
- Integrate with Linux quota subsystem

### Task 6.5: SACL Query/Set

Implement SACL in security descriptor handling:
- Modify: `smbacl.c`

### Task 6.6: Missing File Info Classes

Register handlers for: FILE_PIPE_INFORMATION, FILE_VALID_DATA_LENGTH_INFORMATION, FILE_NORMALIZED_NAME_INFORMATION, etc.

### Task 6.7: Missing FSCTLs

Register handlers for: FSCTL_PIPE_WAIT, FSCTL_PIPE_PEEK, FSCTL_FILE_LEVEL_TRIM, FSCTL_OFFLOAD_READ/WRITE, etc.

### Task 6.8: RDMA Transform Capabilities Negotiate Context

Implement the missing negotiate context for RDMA + encryption.

### Task 6.9: Lock Sequence Validation

Complete lock sequence number validation for resilient handles.

### Task 6.10: GCM Nonce Tracking

Track GCM nonces per-session to prevent reuse:
- Modify: `auth.c`

---

## Phase 7: Testing & CI/CD

**Objective:** Build comprehensive testing infrastructure for mainline-quality confidence.

**Depends on:** Phases 1-5 (testable codebase)

### Task 7.1: KUnit Test Framework

**Files:**
- Create: `test/ksmbd_test_ndr.c`
- Create: `test/ksmbd_test_acl.c`
- Create: `test/ksmbd_test_misc.c`
- Create: `test/ksmbd_test_credit.c`
- Create: `test/ksmbd_test_oplock.c`
- Create: `test/ksmbd_test_config.c`
- Create: `test/Makefile`
- Modify: `Kconfig` (add KUnit test option)

```c
#ifdef CONFIG_KSMBD_KUNIT_TEST

static void test_ndr_encode_decode_roundtrip(struct kunit *test)
{
    struct xattr_dos_attrib da = { .version = 4, .attr = 0x20 };
    char buf[256];
    int len;

    len = ndr_encode_dos_attr(&da, buf, sizeof(buf));
    KUNIT_ASSERT_GT(test, len, 0);

    struct xattr_dos_attrib da2;
    KUNIT_ASSERT_EQ(test, ndr_decode_dos_attr(&da2, buf, len), 0);
    KUNIT_EXPECT_EQ(test, da.attr, da2.attr);
}

#endif
```

### Task 7.2: Fuzzing Harnesses

**Files:**
- Create: `test/fuzz/smb2_header_fuzz.c`
- Create: `test/fuzz/asn1_fuzz.c`
- Create: `test/fuzz/create_context_fuzz.c`
- Create: `test/fuzz/ndr_fuzz.c`
- Create: `test/fuzz/path_parse_fuzz.c`

syzkaller-compatible harnesses for all security-critical parsing code.

### Task 7.3: CI/CD Pipeline

**Files:**
- Create: `.github/workflows/build.yml`
- Create: `.github/workflows/test.yml`

```yaml
name: Build and Test
on: [push, pull_request]
jobs:
  build:
    strategy:
      matrix:
        kernel: ['6.1', '6.6', '6.8', '6.12']
    steps:
      - name: Build ksmbd module
        run: make KDIR=/path/to/kernel-${{ matrix.kernel }}
      - name: Run sparse
        run: make C=2
      - name: Run smatch
        run: make CHECK=smatch
  kunit:
    steps:
      - name: Run KUnit tests
        run: ./tools/testing/kunit/kunit.py run --kconfig_add CONFIG_KSMBD_KUNIT_TEST=y
  integration:
    needs: build
    steps:
      - name: smbtorture
        run: ./tests/run_integration.sh
```

### Task 7.4: Integration Test Harness

**Files:**
- Create: `tests/run_integration.sh`
- Create: `tests/smb.conf.test`

---

## Phase 8: Modular Architecture

**Objective:** Decompose the monolith into independently loadable modules with a stable API. This is the capstone work that makes ksmbd truly extensible.

**Depends on:** All previous phases

### Task 8.1: Decompose smb2pdu.c

**Files:**
- Create: `smb2_negotiate.c`
- Create: `smb2_session.c`
- Create: `smb2_tree.c`
- Create: `smb2_create.c`
- Create: `smb2_read_write.c`
- Create: `smb2_query_set.c`
- Create: `smb2_dir.c`
- Create: `smb2_ioctl.c`
- Create: `smb2_lock.c`
- Create: `smb2_notify.c`
- Create: `smb2_misc_cmds.c`
- Create: `smb2_pdu_common.c`
- Modify: `Makefile`

Split the ~10,000-line `smb2pdu.c` into 12 focused files (~500-2000 lines each). Each file handles one command group. Shared helpers go in `smb2_pdu_common.c`.

**This is the single most impactful refactoring for maintainability.**

### Task 8.2: Hook System (Netfilter-Inspired)

**Files:**
- Create: `ksmbd_hooks.c`
- Create: `ksmbd_hooks.h`
- Modify: `Makefile`

```c
enum ksmbd_hook_point {
    KSMBD_HOOK_PRE_NEGOTIATE,
    KSMBD_HOOK_POST_NEGOTIATE,
    KSMBD_HOOK_PRE_SESSION_SETUP,
    KSMBD_HOOK_POST_SESSION_SETUP,
    KSMBD_HOOK_PRE_TREE_CONNECT,
    KSMBD_HOOK_POST_TREE_CONNECT,
    KSMBD_HOOK_CHECK_ACCESS,
    KSMBD_HOOK_PRE_CREATE,
    KSMBD_HOOK_POST_CREATE,
    KSMBD_HOOK_PRE_READ,
    KSMBD_HOOK_POST_READ,
    KSMBD_HOOK_PRE_WRITE,
    KSMBD_HOOK_POST_WRITE,
    KSMBD_HOOK_PRE_CLOSE,
    KSMBD_HOOK_POST_CLOSE,
    KSMBD_HOOK_PRE_LOCK,
    KSMBD_HOOK_POST_LOCK,
    KSMBD_HOOK_READDIR_ENTRY,
    KSMBD_HOOK_NOTIFY_CHANGE,
    KSMBD_HOOK_CONN_INIT,
    KSMBD_HOOK_CONN_CLEANUP,
    KSMBD_HOOK_AUDIT,
    /* ... total ~31 hook points */
    __KSMBD_HOOK_MAX,
};

/* Zero-cost when no hooks registered */
DECLARE_STATIC_KEY_FALSE(ksmbd_hooks_active);

#define KSMBD_RUN_HOOKS(point, work, ...) ({                     \
    int __ret = KSMBD_HOOK_CONTINUE;                             \
    if (static_branch_unlikely(&ksmbd_hooks_active))             \
        __ret = __ksmbd_run_hooks(point, work, ##__VA_ARGS__);   \
    __ret;                                                       \
})
```

### Task 8.3: Per-Connection Extension State

**Files:**
- Modify: `connection.h`

```c
#define KSMBD_MAX_EXTENSIONS 8

struct ksmbd_conn {
    /* ... existing fields ... */
    void *ext_data[KSMBD_MAX_EXTENSIONS];
};
```

Each module (Fruit, DFS, VSS, audit) gets a slot via registration.

### Task 8.4: Stable Public API

**Files:**
- Create: `include/ksmbd/ksmbd_api.h`

```c
#define KSMBD_API_VERSION_MAJOR 1
#define KSMBD_API_VERSION_MINOR 0

/* Opaque types for module use */
struct ksmbd_work;
struct ksmbd_file;
struct ksmbd_conn;

/* ~40 exported functions */
EXPORT_SYMBOL_GPL(ksmbd_register_fsctl);
EXPORT_SYMBOL_GPL(ksmbd_unregister_fsctl);
EXPORT_SYMBOL_GPL(ksmbd_register_create_context);
EXPORT_SYMBOL_GPL(ksmbd_unregister_create_context);
EXPORT_SYMBOL_GPL(ksmbd_register_info_handler);
EXPORT_SYMBOL_GPL(ksmbd_register_hook);
EXPORT_SYMBOL_GPL(ksmbd_register_transport);
EXPORT_SYMBOL_GPL(ksmbd_register_auth_provider);
/* ... accessors for opaque types ... */
```

### Task 8.5: Extract Transport Modules

Extract `ksmbd-transport-tcp` and `ksmbd-transport-rdma` as separate `.ko` modules using the transport factory registration API.

### Task 8.6: Extract Authentication Modules

Extract `ksmbd-auth-ntlm` and `ksmbd-auth-krb5` as separate `.ko` modules using the auth provider registration API.

### Task 8.7: Extract Feature Modules

Extract as separate `.ko` modules:
- `ksmbd-fruit` (Apple extensions)
- `ksmbd-dfs` (Distributed File System)
- `ksmbd-vss` (Volume Shadow Copy)
- `ksmbd-acl` (ACL engine)
- `ksmbd-audit` (Audit logging)

Each module uses the hook system and FSCTL/create-context registration APIs.

### Task 8.8: Break Circular Header Dependencies

Refactor headers into a layered DAG:
```
Layer 0: ksmbd_types.h (basic type definitions, no dependencies)
Layer 1: ksmbd_api.h (public API, depends only on Layer 0)
Layer 2: ksmbd_*_internal.h (implementation details, depends on Layers 0-1)
Layer 3: Individual .c files (depend on Layers 0-2)
```

### Task 8.9: Authentication Provider Registration API

```c
struct ksmbd_auth_provider {
    const char *name;
    unsigned int mech_type;
    int (*authenticate)(struct ksmbd_session *sess,
                        struct ksmbd_conn *conn,
                        void *sec_blob, size_t blob_len,
                        void **rsp_blob, size_t *rsp_len);
    int (*derive_session_key)(struct ksmbd_session *sess);
    struct list_head list;
};

int ksmbd_register_auth_provider(struct ksmbd_auth_provider *p);
void ksmbd_unregister_auth_provider(struct ksmbd_auth_provider *p);
```

### Task 8.10: Transport Factory Registration API

```c
struct ksmbd_transport_factory {
    const char *name;
    int (*create_listener)(struct ksmbd_transport_factory *f,
                           struct ksmbd_transport **out);
    void (*destroy)(struct ksmbd_transport_factory *f);
    struct list_head list;
};

int ksmbd_register_transport(struct ksmbd_transport_factory *f);
void ksmbd_unregister_transport(struct ksmbd_transport_factory *f);
```

### Task 8.11: SMB1 Clean Separation

Move ALL `#ifdef CONFIG_SMB_INSECURE_SERVER` blocks from shared files into SMB1-specific files. Register SMB1 via the protocol version registration API. Eventually extractable as a separate module.

---

## Dependency Graph (Simplified)

```
Phase 1 ──────────────────────────────────────────────────────┐
  (Security Hardening)                                        │
       │                                                      │
       ├──→ Phase 2 ─────────────────────┐                    │
       │     (Registration APIs)         │                    │
       │          │                      │                    │
       │          ├──→ Phase 3           │                    │
       │          │     (Features)       │                    │
       │          │          │           │                    │
       │          ├──────────┼──→ Phase 6                     │
       │          │          │    (Protocol)                  │
       │          │          │                                │
       ├──→ Phase 4 ────────┤                                │
       │     (Performance)  │                                │
       │                    │                                │
       ├──→ Phase 5 ────────┤                                │
       │     (Safety)       │                                │
       │                    │                                │
       └──→ Phase 7 ────────┼──→ Phase 8                     │
            (Testing)       │    (Modular Architecture)      │
                            │                                │
                            └────────────────────────────────┘
```

**Phases 4 and 5 can run in parallel with Phases 2 and 3** (different files, no dependency).

**Phase 7 (Testing) should start early and run continuously.**

**Phase 8 must wait for all others** (it restructures the entire codebase).

---

## Execution Strategy

### For Subagent-Driven Development

Each **Task** (1.1, 1.2, ..., 8.11) is a discrete work unit for one subagent invocation. Total: ~55 tasks.

**Parallelizable pairs within each phase:**

| Phase | Parallel Groups |
|-------|----------------|
| 1 | {1.1, 1.5, 1.9} || {1.2, 1.3, 1.6} || {1.4, 1.7, 1.8, 1.10} |
| 2 | {2.1, 2.3, 2.5} || {2.2, 2.4, 2.6} |
| 3 | {3.1, 3.4} || {3.2, 3.3} || {3.5, 3.6} |
| 4 | {4.1, 4.2, 4.4} || {4.3, 4.5, 4.6, 4.7} |
| 5 | {5.1, 5.3} || {5.2, 5.4, 5.5, 5.6} |
| 6 | {6.1, 6.4, 6.5} || {6.2, 6.3} || {6.6, 6.7, 6.8, 6.9, 6.10} |
| 7 | {7.1, 7.3} || {7.2, 7.4} |
| 8 | {8.1} then {8.2, 8.3, 8.4, 8.8} then {8.5, 8.6, 8.7, 8.9, 8.10, 8.11} |

### Commit Strategy

- **One commit per task** (atomic, reviewable)
- **Every commit must build** (`make` succeeds)
- **Every phase ends with a smbtorture run** to verify no regressions
- **Commit message format:** `category: description [finding IDs]`

### Quality Gates

| Gate | When | Pass Criteria |
|------|------|---------------|
| G1 | After Phase 1 | `make` clean, module loads, no new warnings |
| G2 | After Phase 2 | All registration APIs have KUnit tests |
| G3 | After Phase 3 | Windows Explorer auto-refresh, Previous Versions tab works |
| G4 | After Phase 4 | smbtorture throughput >= baseline |
| G5 | After Phase 5 | No KASAN/KMSAN findings under stress |
| G6 | After Phase 6 | smbtorture full suite pass rate > 95% |
| G7 | After Phase 7 | CI/CD green, KUnit > 100 tests, fuzzing 24h clean |
| G8 | After Phase 8 | All modules load/unload cleanly, API versioned |

---

## Estimated Scope

| Phase | New Files | Modified Files | New Lines | Effort |
|-------|-----------|----------------|-----------|--------|
| 1 | 0 | 12 | ~500 | M |
| 2 | 8 | 8 | ~3,000 | L |
| 3 | 6 | 6 | ~5,000 | XL |
| 4 | 2 | 8 | ~1,500 | L |
| 5 | 0 | 6 | ~800 | M |
| 6 | 0 | 6 | ~2,000 | L |
| 7 | 12 | 2 | ~4,000 | L |
| 8 | 20 | 15 | ~8,000 | XL |
| **Total** | **48** | **~40** | **~25,000** | |

---

## Success Criteria: Mainline Readiness

When complete, ksmbd will meet these criteria for mainline kernel inclusion:

1. **Zero known security vulnerabilities** (all CRITICAL/HIGH/MEDIUM fixed)
2. **No global lock contention** in READ/WRITE hot path
3. **Full CHANGE_NOTIFY** support (Windows Explorer auto-refresh)
4. **DFS and VSS** support for enterprise deployment
5. **100+ KUnit tests** with CI/CD on every commit
6. **Fuzzing infrastructure** with 24h clean run
7. **Modular architecture** with stable extension API
8. **smb2pdu.c decomposed** from 10K lines to 12 files of 500-2K lines each
9. **All features runtime-toggleable** without recompilation
10. **Documentation** in kernel style (kernel-doc comments on all public APIs)

---

*End of Master Implementation Plan*
*145 items, 8 phases, ~55 tasks, ~25,000 new lines of code*
