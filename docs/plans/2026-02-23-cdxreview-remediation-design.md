# CDXREVIEW Remediation Design

**Date:** 2026-02-23
**Branch:** `phase1-security-hardening`
**Scope:** 9 findings from CDXREVIEW audit (CRIT x1, HIGH x2, MED x4, LOW x2)

## Architecture Context

ksmbd is a kernel SMB3 server module. The CHANGE_NOTIFY subsystem (`ksmbd_notify.c`) uses Linux fsnotify to watch directories and deliver asynchronous SMB2 responses. The userspace daemon (`ksmbd-tools/mountd`) handles RPC, config, and user management over Generic Netlink.

## Approach: Fix in priority order, one commit per severity tier

### Tier 1: Critical + High (CRIT-001, HIGH-002, HIGH-003)

**CRIT-001: CHANGE_NOTIFY UAF — refcount-decouple watch from work lifetime**

The root cause is that `ksmbd_notify_watch` stores a raw `pending_work` pointer to `struct ksmbd_work`, but `work` is freed by the worker thread (`server.c:289`) independently of the watch's lifetime. Three paths race:

1. **Worker completion** (`handle_ksmbd_work`): frees `work` after `release_async_work` nulls `cancel_fn`/`cancel_argv`
2. **Notify event** (`ksmbd_notify_build_response`): dereferences `watch->pending_work`
3. **File close** (`ksmbd_notify_cleanup_file`): iterates `fp->blocked_works` accessing `work` members

Fix:
- Add `struct kref refcount` to `ksmbd_notify_watch`
- Worker path: before freeing work, detach from watch under `watch->lock`, put watch ref
- Notify callback: take ref, check work validity under lock, put ref after response
- File close: take ref, detach under lock, put ref after cleanup
- Move `cancel_argv` ownership: don't let `release_async_work` free it when notify owns it

**HIGH-002: FSNOTIFY_GROUP_NOFS build break**

`FSNOTIFY_GROUP_NOFS` doesn't exist in kernel 6.17. Add a compat check:
```c
#if defined(FSNOTIFY_GROUP_NOFS)
  flags = FSNOTIFY_GROUP_NOFS;
#elif defined(FSNOTIFY_GROUP_USER)
  flags = FSNOTIFY_GROUP_USER;
#else
  flags = 0;
#endif
```

**HIGH-003: rpc_samr.c off-by-one heap overflow**

Replace `g_try_malloc0` + `strcat` chain with single `g_strdup_printf`:
```c
profile_path = g_strdup_printf("\\\\%s\\%s\\profile", hostname, user->name);
```

### Tier 2: Medium (MED-004, MED-005, MED-006, MED-007)

**MED-004: run_tests.sh broken** — Fix logging init order, align paths with actual tree.

**MED-005: CI validates presence not behavior** — Add real build verification step; at minimum compile the module in CI rather than counting files.

**MED-006: Fruit docs exceed code** — Add explicit `[STUB]` markers to incomplete handler functions and update README claims.

**MED-007: Checkpatch compliance** — Fix the worst hotspot files (memory_usage_validator.c, auth.c, transport_rdma.c). Focus on errors first, then critical warnings.

### Tier 3: Low (LOW-008, LOW-009)

**LOW-008: Benchmark methodology** — Add `--iterations` flag and variance reporting to benchmark runner.

**LOW-009: Manpage coverage** — Already substantially addressed by the ksmbdctl.8.in expansion (commit 3725084). Remaining gap: ksmbd.conf.5 could use section on new features.

## Verification

Each tier must:
1. Build cleanly: `make -j$(nproc) W=1`
2. No new warnings introduced
3. Committed and buildable independently
