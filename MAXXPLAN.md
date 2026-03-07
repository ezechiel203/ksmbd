# MAXXPLAN: Future Apple/macOS Compatibility Work

> Deferred features and enhancements for full Apple ecosystem compatibility.
> These items were identified during the Apple compatibility audit but are
> out of scope for the initial kAAPL wire protocol and config flag work.

---

## 1. Bonjour/mDNS Service Discovery

**Priority:** High
**Difficulty:** Low (userspace-only, no kernel changes)

**What:** macOS Finder discovers SMB shares via Bonjour (mDNS/DNS-SD). Two service types must be advertised:
- `_smb._tcp` — Standard SMB file sharing service
- `_adisk._tcp` — Apple disk service (enables Time Machine discovery)

**Why:** Without Bonjour, macOS users must manually enter `smb://server/share` instead of seeing the server in Finder's Network sidebar. Time Machine cannot auto-discover backup destinations.

**Implementation:**
- Configure Avahi (or systemd-resolved) to advertise `_smb._tcp` on port 445
- For Time Machine shares, also advertise `_adisk._tcp` with TXT records:
  ```
  sys=adVF=0x82
  dk0=adVN=ShareName,adVF=0x82
  ```
  (where `adVN` is the share name and `adVF=0x82` indicates Time Machine support)
- This is entirely a userspace/system configuration task — ksmbd.mountd or a helper script should generate the Avahi service files from ksmbd.conf

**Files to create/modify:**
- `docs/bonjour-setup.md` — documentation
- `contrib/avahi/ksmbd-smb.service` — template Avahi service file
- `contrib/avahi/ksmbd-timemachine.service` — template for Time Machine shares
- `ksmbd.mountd` (userspace) — auto-generate Avahi service files from share config

---

## 2. Spotlight / mdssvc Integration

**Priority:** Medium
**Difficulty:** Very High

**What:** macOS Spotlight search can query SMB servers for file metadata via the mdssvc RPC pipe. This enables searching file contents and metadata from Finder's search bar on mounted SMB shares.

**Why:** Without Spotlight, users cannot search file contents on mounted ksmbd shares from Finder. The search bar shows "Searching..." indefinitely.

**Implementation:**
This is a major project requiring:
1. **DCE/RPC pipe handler** for the `mdssvc` named pipe — must handle Spotlight query protocol
2. **Search index backend** — integration with a Linux search indexer (Tracker, Recoll, or mlocate)
3. **Query translation** — convert macOS Spotlight queries (kMDItemDisplayName, kMDItemContentType, etc.) to the search backend's query format
4. **Result marshalling** — pack search results into the mdssvc RPC response format

**Reference:** Samba's `vfs_fruit` + `mds_tracker` module implements this using GNOME Tracker. See `source3/rpc_server/mdssvc/` in Samba source.

**Estimated scope:** ~5000+ lines of new code across kernel + userspace

---

## 3. kAAPL_RESOLVE_ID (File ID Resolution)

**Priority:** Low
**Difficulty:** Medium

**What:** When `kAAPL_SUPPORT_RESOLVE_ID` is set in `volume_caps`, macOS can send an IOCTL to resolve a file ID (inode number) back to its full path. This enables features like "Show Original" for aliases and efficient file tracking.

**Why:** Without this, macOS aliases (similar to symlinks but track by file ID) cannot resolve their targets on ksmbd shares. This is a niche feature — most users won't notice.

**Implementation:**
1. Add a new SMB2 IOCTL handler for the Apple RESOLVE_ID IOCTL code
2. Implement inode-to-path resolution using `d_path()` or `exportfs_decode_fh()`
3. Set `kAAPL_SUPPORT_RESOLVE_ID` in `volume_caps` when the feature is ready
4. Handle edge cases: deleted files, renamed files, cross-mount-point resolution

**Files to modify:**
- `smb2pdu.c` — add IOCTL handler
- `vfs.c` — add `ksmbd_vfs_resolve_fileid()` helper
- `oplock.c` — set `kAAPL_SUPPORT_RESOLVE_ID` in volume_caps

---

## 4. Full FinderInfo/ResourceFork in ReadDirAttr

**Priority:** Medium
**Difficulty:** Medium-High

**What:** The current ReadDirAttr implementation packs UNIX mode bits into the EaSize field. The full Apple protocol also includes:
- **FinderInfo** (32 bytes): Creator/type codes, Finder flags, icon position
- **Resource fork size** (8 bytes): Size of the `AFP_Resource` alternate data stream
- **Max access rights** (4 bytes): Per-file access mask

These are packed after the standard directory entry fields when `kAAPL_SUPPORTS_READ_DIR_ATTR` is negotiated.

**Why:** Without full enrichment, Finder may show incorrect icons for some file types and must make individual QUERY_INFO calls for resource fork sizes and access rights. The UNIX mode injection (Task 6) handles the most critical performance issue, but full enrichment would complete the protocol.

**Implementation:**
1. For each directory entry, read `com.apple.FinderInfo` xattr (32 bytes)
2. Read `user.DosStream.AFP_Resource:$DATA` xattr to get resource fork size
3. Compute max_access for the file based on current user permissions
4. Pack these values into the ReadDirAttr extension area after each entry

**Performance concern:** Reading xattrs per directory entry is expensive. Consider:
- Batched xattr reads (if VFS supports it)
- Caching FinderInfo in the dentry or inode
- Only enabling full enrichment via per-share config flag (`FRUIT_FINDER_INFO`, `FRUIT_RFORK_SIZE`, `FRUIT_MAX_ACCESS`)
- The per-share flags for this already exist in the kernel header

**Files to modify:**
- `smb2fruit.c:smb2_read_dir_attr_fill()` — extend with xattr reads
- `smb2pdu.c` — adjust entry size calculation for extended data
- `vfs.c` — add xattr read helpers optimized for batch operations

---

## 5. Server-side OSX_COPYFILE IOCTL

**Priority:** Low
**Difficulty:** Medium

**What:** When `kAAPL_SUPPORTS_OSX_COPYFILE` is negotiated, macOS can send an IOCTL to request server-side file copy that preserves Apple metadata (resource forks, FinderInfo, extended attributes). This is separate from SMB2 COPYCHUNK (which ksmbd already supports for data-only copies).

**Why:** Without this, copying files between folders on the same share requires macOS to download and re-upload the entire file plus all metadata streams. With server-side copy, it's a single kernel VFS operation.

**Implementation:**
1. Add IOCTL handler for the Apple COPYFILE IOCTL code
2. Use `vfs_copy_file_range()` for the data fork (already exists in ksmbd)
3. Copy all `user.*` xattrs from source to destination (preserves FinderInfo, resource fork, etc.)
4. Preserve POSIX ACLs if `FRUIT_NFS_ACES` is enabled

**Note:** The `kAAPL_SUPPORTS_OSX_COPYFILE` flag is already wired to `server_caps` via `KSMBD_GLOBAL_FLAG_FRUIT_COPYFILE`. The IOCTL handler is the missing piece.

**Files to modify:**
- `smb2pdu.c` — add IOCTL handler in `smb2_ioctl()`
- `vfs.c` — add `ksmbd_vfs_copyfile()` that copies data + xattrs

---

## 6. AFP_AfpInfo Stream Synthesis

**Priority:** Medium
**Difficulty:** Medium

**What:** macOS stores FinderInfo metadata in the `AFP_AfpInfo` named stream (alternate data stream in SMB terms). When a client reads `FILE:AFP_AfpInfo:$DATA`, the server should synthesize a 60-byte AfpInfo structure from the `com.apple.FinderInfo` xattr if the DosStream xattr doesn't exist. This handles migration from netatalk/AFP servers.

**Why:** Files migrated from AFP servers (netatalk) have `com.apple.FinderInfo` xattrs but not `user.DosStream.AFP_AfpInfo:$DATA`. Without synthesis, Finder shows incorrect icons and metadata for migrated files.

**Implementation:**
The AfpInfo structure (60 bytes):
```c
struct afp_info {
    char      magic[4];       /* "AFP\0" */
    uint32_t  version;        /* 0x00010000 */
    uint32_t  file_id;        /* 0 */
    uint32_t  backup_type;    /* 0 */
    uint8_t   finder_info[32]; /* from com.apple.FinderInfo xattr */
    uint8_t   prodos_info[6]; /* 0 */
    uint16_t  padding;        /* 0 */
};
```

1. In `ksmbd_vfs_stream_read()`, intercept reads of `:AFP_AfpInfo:$DATA`
2. If `user.DosStream.AFP_AfpInfo:$DATA` exists, return it as-is
3. Otherwise, check for `com.apple.FinderInfo` xattr
4. If found, synthesize the 60-byte AfpInfo structure
5. Similarly intercept writes to keep both xattrs in sync

**Files to modify:**
- `vfs.c:ksmbd_vfs_stream_read()` — add interception logic
- `vfs.c:ksmbd_vfs_stream_write()` — keep xattrs in sync
- `smb2fruit.h` — AfpInfo structure definition (constants already added)

---

## 7. Full Time Machine Metadata Synthesis

**Priority:** High (for Time Machine support)
**Difficulty:** Low-Medium

**What:** macOS Time Machine checks for specific xattrs on the share root directory:
- `com.apple.timemachine.supported` — indicates the volume supports Time Machine
- `com.apple.timemachine.MaxSize` — maximum backup size (optional)

When `KSMBD_SHARE_FLAG_FRUIT_TIME_MACHINE` is set, the server should synthesize these xattrs in the QUERY_INFO response for the share root.

**Why:** Without these xattrs, Time Machine will not list the volume as a backup destination in System Preferences.

**Implementation:**
1. In the SMB2 QUERY_INFO handler for `FILE_STREAM_INFORMATION`, detect when the queried path is the share root
2. If `KSMBD_SHARE_FLAG_FRUIT_TIME_MACHINE` is set on the share, inject the Time Machine xattrs
3. For `com.apple.timemachine.MaxSize`, use the share's `time_machine_max_size` value (already plumbed through ksmbd_netlink)
4. Also handle TIME_MACHINE xattr enumeration (QUERY_DIRECTORY with xattr listing)

**Files to modify:**
- `smb2pdu.c:smb2_get_info_file()` — inject xattrs for share root
- `vfs.c` — add helper to check if a path is the share root

---

## 8. Persistent File Handles for Apple Clients

**Priority:** Low
**Difficulty:** High

**What:** macOS SMB clients support persistent file handles (durable handles v2) for resilient file access across brief network interruptions. The `KSMBD_GLOBAL_FLAG_DURABLE_HANDLE` flag exists but the implementation may not fully handle Apple client reconnection patterns.

**Why:** Without robust persistent handles, macOS users experience "The operation can't be completed because the original item can't be found" errors when a Wi-Fi connection briefly drops and reconnects.

**Implementation:**
1. Audit the existing durable handle implementation for Apple client compatibility
2. Ensure handle reconstitution works with Apple's SMB2 CREATE with `SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2`
3. Test with actual macOS clients under network disruption scenarios

**Files to audit:**
- `oplock.c` — durable handle implementation
- `smb2pdu.c` — CREATE handler durable handle processing
- `vfs_cache.c` — file handle lifecycle

---

## 9. POSIX Extensions for macOS

**Priority:** Low
**Difficulty:** Medium

**What:** SMB3.1.1 POSIX extensions (MS-SMB2 2.2.1.1) allow proper UNIX semantics (case sensitivity, POSIX paths, proper UID/GID mapping). macOS 13+ supports negotiating POSIX extensions.

**Why:** Without POSIX extensions, macOS must use the traditional Windows semantics which causes issues with:
- Case sensitivity (macOS is case-insensitive, Linux is case-sensitive)
- Symlink handling (macOS symlinks vs Windows reparse points)
- UID/GID preservation (important for development workflows)

**Implementation:**
1. Add POSIX extension negotiation in SMB2 NEGOTIATE
2. Implement POSIX path handling (no backslash translation)
3. Implement POSIX create context for proper mode/UID/GID
4. Wire to the existing POSIX locks support

---

## Implementation Priority Order

| Priority | Feature | Impact | Effort |
|----------|---------|--------|--------|
| 1 | Bonjour/mDNS (#1) | High — enables auto-discovery | Low |
| 2 | Time Machine Metadata (#7) | High — enables Time Machine | Low-Med |
| 3 | AFP_AfpInfo Synthesis (#6) | Medium — migration support | Medium |
| 4 | Full ReadDirAttr (#4) | Medium — Finder perf | Med-High |
| 5 | OSX_COPYFILE IOCTL (#5) | Low — copy performance | Medium |
| 6 | kAAPL_RESOLVE_ID (#3) | Low — alias resolution | Medium |
| 7 | Persistent Handles (#8) | Low — resilience | High |
| 8 | POSIX Extensions (#9) | Low — dev workflows | Medium |
| 9 | Spotlight/mdssvc (#2) | Medium — search | Very High |
