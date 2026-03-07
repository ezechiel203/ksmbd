# Persistent-Handle Delta Review

Scope:
- Follow-up to `persistent-handles.md`.
- Covers implementation work for the persistent-handle backend, not just the initial review findings.

Implemented:
1. The real persistent-handle backend is now linked into the module build.
   - `Makefile:47` now includes `src/protocol/smb2/smb2_ph.o` in `ksmbd-y`.
   - The local stub helpers were removed from `src/protocol/smb2/smb2_create.c`, and shared prototypes now live in `src/include/protocol/smb2pdu.h`.

2. Persistent-handle capability advertisement and create-time enablement are back in sync with the backend.
   - `src/protocol/smb2/smb2ops.c:298`, `src/protocol/smb2/smb2ops.c:336`, and `src/protocol/smb2/smb2ops.c:376` advertise `SMB2_GLOBAL_CAP_PERSISTENT_HANDLES` again when durable handles are enabled.
   - `src/protocol/smb2/smb2_create.c:2769` now honors `SMB2_DHANDLE_FLAG_PERSISTENT` for DH2Q v2 requests and sets `fp->is_persistent` when the server advertises the capability.
   - `src/protocol/smb2/smb2_create.c:2791` now saves persistent-handle state via the shared backend.

3. Restore now re-registers the recovered handle under the original persistent ID and keeps it confined to the share root.
   - `src/include/fs/vfs_cache.h:265` and `src/fs/vfs_cache.c:1155` add exact-ID durable registration.
   - `src/protocol/smb2/smb2_ph.c:181` validates the persisted record before use.
   - `src/protocol/smb2/smb2_ph.c:232` rejects restores that reopen outside `work->tcon->share_conf->vfs_path`.
   - `src/protocol/smb2/smb2_ph.c:252` restores the original persistent ID instead of allocating a new one and overwriting the field afterward.

4. Restore now rebuilds oplock/lease state instead of returning a bare `ksmbd_file`.
   - `src/fs/oplock.c:3111` adds `ksmbd_restore_oplock()`.
   - `src/protocol/smb2/smb2_ph.c:259` reconstructs the saved lease/oplock metadata and publishes a real `fp->f_opinfo` before reconnect processing continues.
   - The persisted record now includes `client_guid`, oplock level, and lease metadata needed by reconnect validation.

5. Close-path cleanup now preserves persistent state across failed restore attempts while still deleting it on real final close.
   - `src/include/fs/vfs_cache.h:157` adds `persistent_restore_pending`.
   - `src/protocol/smb2/smb2_ph.c:251` marks restored-but-not-yet-reconnected handles as pending.
   - `src/fs/vfs_cache.c:542` skips `ksmbd_ph_delete()` while that flag is set, preventing a failed reconnect attempt from deleting the saved persistent state.
   - `src/fs/vfs_cache.c:1817` clears the flag after `ksmbd_reopen_durable_fd()` succeeds.

6. Restore no longer falls back to `O_RDONLY` when the saved access mask requires write access.
   - `src/protocol/smb2/smb2_ph.c:203` derives whether the persisted handle needs write-capable reopening.
   - `src/protocol/smb2/smb2_ph.c:224` only allows `O_RDONLY` fallback for read-only handles.

Validation:
- `git diff --check` passed for the touched files.
- Kernel compile validation is still blocked because `/lib/modules/6.18.9-arch1-2/build` is missing.

Residual risk:
- This pass did not compile or execute the kernel module, so integration issues may still exist until the tree is build-tested against matching kernel headers.
- The backend persists enough state for reconnect validation, but it still does not attempt to reconstruct any in-flight break/wait state from before a crash; restored handles come back in a steady-state oplock/lease configuration.
