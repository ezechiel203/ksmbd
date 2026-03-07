# Persistent-Handle Backend Review

Findings:
1. High: the real persistent-handle backend is not linked into the module, so the active code path is still the stub implementation in `smb2_create.c`.
   - `Makefile:47` through `Makefile:70` never add `src/protocol/smb2/smb2_ph.o` to `ksmbd-y`.
   - `src/protocol/smb2/smb2_create.c:896`, `src/protocol/smb2/smb2_create.c:913`, and `src/protocol/smb2/smb2_create.c:929` still define local stub `ksmbd_ph_save()`, `ksmbd_ph_restore()`, and `ksmbd_ph_delete()`.
   - Result: the backend in `src/protocol/smb2/smb2_ph.c` is dead code in the current build, and persistent-handle restart recovery cannot work regardless of the code in that file.

2. High: if `smb2_ph.c` is wired in, `ksmbd_ph_restore()` corrupts the durable-handle IDR mapping by allocating one persistent ID and then overwriting `fp->persistent_id` with a different one.
   - `src/protocol/smb2/smb2_ph.c:182` calls `ksmbd_open_durable_fd(fp)`, which inserts `fp` into `global_ft.idr` under a newly allocated ID.
   - `src/protocol/smb2/smb2_ph.c:183` immediately overwrites `fp->persistent_id = persistent_id`.
   - `src/fs/vfs_cache.c:1112` through `src/fs/vfs_cache.c:1148` show that `ksmbd_open_durable_fd()` stores the allocated ID directly into both the IDR key and `fp->persistent_id`; changing the field afterward does not retag the IDR entry.
   - Result: later lookups by the restored persistent ID miss, while close-time cleanup attempts to remove a different ID than the one actually stored in the IDR.

3. High: if `smb2_ph.c` is wired in, a restored handle still cannot survive a restart because restore never reconstructs oplock/lease state, and reconnect explicitly rejects durable/persistent handles with no `opinfo`.
   - `src/protocol/smb2/smb2_ph.c:171` through `src/protocol/smb2/smb2_ph.c:182` rebuild a `ksmbd_file`, but they do not restore `f_opinfo`, lease key, or replay state.
   - `src/fs/oplock.c:3017` through `src/fs/oplock.c:3026` reject reconnect with `-EBADF` when `opinfo_get(fp)` returns `NULL` for a durable or persistent handle.
   - `src/protocol/smb2/smb2_create.c:1718` through `src/protocol/smb2/smb2_create.c:1724` call that check unconditionally before `ksmbd_reopen_durable_fd()`.
   - Result: even a successfully restored `ksmbd_file` would be rejected during reconnect, so restart persistence is still incomplete.

4. Medium: the restore path bypasses the normal share-root confinement checks and reopens an absolute kernel path after validating only the share name string.
   - `src/protocol/smb2/smb2_ph.c:155` through `src/protocol/smb2/smb2_ph.c:168` compare `work->tcon->share_conf->name` and then call `kern_path(fp_path, LOOKUP_FOLLOW, ...)` on the stored absolute path.
   - The normal create/open path performs a post-open share-boundary check at `src/protocol/smb2/smb2_create.c:2342` through `src/protocol/smb2/smb2_create.c:2348`, using `path_is_under()` as documented in `src/fs/vfs.c:65` through `src/fs/vfs.c:78`.
   - Result: if a share keeps the same name but its root changes, or if the stored absolute path is no longer inside the current export root, restore can resurrect a handle to a path the current share configuration should not expose.

Open questions:
- `src/protocol/smb2/smb2_ph.c:161` through `src/protocol/smb2/smb2_ph.c:168` fall back from `O_RDWR` to `O_RDONLY` but then restore the original `fp->daccess`. I did not execute this path, so I am treating the resulting access-mode mismatch as a likely follow-up bug rather than a confirmed finding.
- `src/protocol/smb2/smb2_create.c` and `src/protocol/smb2/smb2ops.c` still contain stale comments describing persistence as a stub even though a backend file exists. That is not itself a runtime bug, but it already caused drift in capability gating and review assumptions.

Summary:
- Current build: persistent-handle restart support is effectively disabled because the real backend file is not linked.
- If re-enabled by linking `smb2_ph.c`, the restore path still has correctness and confinement bugs that need to be fixed before advertising the feature.
