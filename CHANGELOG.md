# Changelog: Apple macOS AAPL SMB Extension for ksmbd

> Full Apple/macOS Fruit SMB protocol extension implementation for ksmbd.
> Base version: ksmbd 3.5.3 (commit `f012374`)
> Upstream: [namjaejeon/ksmbd](https://github.com/namjaejeon/ksmbd)
> Companion tools: [namjaejeon/ksmbd-tools](https://github.com/namjaejeon/ksmbd-tools)

---

## Summary

This PR adds comprehensive Apple AAPL SMB protocol support to ksmbd,
enabling macOS Finder, Time Machine, and other Apple SMB clients to work
correctly with ksmbd-served shares. The implementation follows Apple's
private AAPL create context extension as documented in Apple's SMB client
source code and observed wire-protocol behavior.

**Scope:** 18 modified kernel source files, 2 new kernel source files
(609 lines), 12 new test files (11,599 lines), 103 unit tests passing.

**Upstream status:** This fork diverges from
[namjaejeon/ksmbd](https://github.com/namjaejeon/ksmbd) at commit
`f012374` (ksmbd release 3.5.3). Upstream has since advanced to v3.5.4
with ~20 additional commits (bug fixes, RDMA refactoring, VFS
delegation improvements). A rebase onto upstream/master will be required
before submitting this PR. The files with potential merge conflicts are:
`smb2pdu.c`, `vfs.c`, `vfs.h`, `vfs_cache.c`, `connection.c`,
`transport_ipc.c`.

**Companion PR required:** The userspace
[namjaejeon/ksmbd-tools](https://github.com/namjaejeon/ksmbd-tools)
must be updated to parse the 10 new configuration options and populate
the modified netlink structs. See [Section 5](#5-userspace-changes-required-ksmbd-tools)
for the exact file-by-file changes.

---

## 1. New Files

### Kernel Module

| File | Lines | Description |
|------|-------|-------------|
| `smb2fruit.h` | 214 | Fruit SMB extension header: wire protocol constants (kAAPL_*), struct definitions for all 7 create context types (server query, volume capabilities, file mode, dir hardlinks, looker/FinderInfo, savebox/TimeMachine, client info), connection state struct, AFP stream constants, function declarations |
| `smb2fruit.c` | 395 | Fruit SMB extension implementation: AAPL signature validation, client info parsing, capability negotiation (config-driven), client version/type detection, create context validation, connection state lifecycle, server response building, debug helpers, ReadDirAttr UNIX mode enrichment |

### Test Framework

| File | Lines | Description |
|------|-------|-------------|
| `test_framework/run_fruit_tests.c` | 1,433 | Primary unit test runner — 103 tests across 26 groups (A-Z) covering all smb2fruit.c functions, kAAPL wire protocol constants, AAPL response wire format, config flag wiring, F_FULLFSYNC detection, ReadDirAttr mode packing. Compiles and runs in userspace. |
| `test_framework/test_utils.h` | 382 | Shared test utilities and mock helpers |
| `test_framework/unit_test_framework.c` | 447 | Supplementary unit tests |
| `test_framework/apple_enhanced_unit_tests.c` | 879 | Apple-specific enhanced unit tests |
| `test_framework/apple_security_tests.c` | 954 | Security-focused tests for Apple protocol handling |
| `test_framework/apple_smb_real_client_testing.c` | 1,034 | Real client behavior simulation tests |
| `test_framework/integration_compatibility_testing.c` | 1,095 | Cross-platform compatibility tests |
| `test_framework/integration_test_framework.c` | 707 | Integration test infrastructure |
| `test_framework/performance_test_framework.c` | 919 | Performance benchmarking tests |
| `test_framework/production_readiness_validation.c` | 1,050 | Production readiness checks |
| `test_framework/smb2_end_to_end_testing.c` | 1,139 | End-to-end SMB2 protocol tests |
| `test_framework/include/linux/slab.h` | ~30 | Userspace stub for kernel slab allocator (kzalloc/kfree -> calloc/free) |

---

## 2. Modified Files — Detailed Changes

### 2.1 `ksmbd_netlink.h` — Kernel-Userspace ABI

**4 new global config flags** (bits 5-8, previously reserved):

```c
#define KSMBD_GLOBAL_FLAG_FRUIT_EXTENSIONS    BIT(5)  /* Enable AAPL extension */
#define KSMBD_GLOBAL_FLAG_FRUIT_ZERO_FILEID   BIT(6)  /* Zero UniqueId in dir listings */
#define KSMBD_GLOBAL_FLAG_FRUIT_NFS_ACES      BIT(7)  /* NFS ACE support */
#define KSMBD_GLOBAL_FLAG_FRUIT_COPYFILE      BIT(8)  /* Server-side copy */
```

**4 new per-share config flags** (bits 17-20, previously reserved):

```c
#define KSMBD_SHARE_FLAG_FRUIT_TIME_MACHINE   BIT(17) /* Time Machine volume */
#define KSMBD_SHARE_FLAG_FRUIT_FINDER_INFO    BIT(18) /* FinderInfo enrichment */
#define KSMBD_SHARE_FLAG_FRUIT_RFORK_SIZE     BIT(19) /* Resource fork size */
#define KSMBD_SHARE_FLAG_FRUIT_MAX_ACCESS     BIT(20) /* Max access rights */
```

**`ksmbd_startup_request`** — carved `fruit_model[64]` from reserved space:

```diff
-  __s8  reserved[499];
+  __s8  fruit_model[64];   /* Fruit model string for AAPL */
+  __s8  reserved[435];
```

**`ksmbd_share_config_response`** — carved `time_machine_max_size` from reserved space:

```diff
-  __u32 reserved[111];
+  __u64 time_machine_max_size; /* Time Machine max size in bytes */
+  __u32 reserved[109];
```

> **ABI compatibility:** Both changes carve fields from existing reserved
> space, maintaining struct size. Existing userspace tools that don't set
> these fields will send zeros, which is the correct default (no fruit
> extensions, no Time Machine limit).

---

### 2.2 `connection.h` / `connection.c` — Connection State

**Header changes:**
- Added `#include "smb2fruit.h"`
- Renamed `is_aapl` -> `is_fruit` (the upstream field was a bare `bool` with no associated state)
- Added `struct fruit_conn_state *fruit_state` to `struct ksmbd_conn`

**Source changes:**
- `ksmbd_conn_free()`: Added cleanup of `fruit_state` (calls `fruit_cleanup_connection_state()` + `kfree`) before connection teardown to prevent memory leaks

---

### 2.3 `server.h` / `server.c` — Server Configuration

**Header changes:**
- Added `char fruit_model[64]` to `struct ksmbd_server_config` — stores the model string sent in AAPL responses (e.g., "MacSamba", "Xserve")

**Source changes:**
- `ksmbd_server_init()`: Calls `fruit_init_module()` during kernel module initialization
- `ksmbd_server_exit()`: Calls `fruit_cleanup_module()` during kernel module unload
- Added `#include "smb2fruit.h"`

---

### 2.4 `transport_ipc.c` — Userspace Configuration Plumbing

- `ipc_server_config_on_startup()`: Copies `req->fruit_model` to `server_conf.fruit_model` via `strscpy()` — plumbs the model string from ksmbd.mountd configuration to the kernel module

---

### 2.5 `smb2pdu.h` — Protocol Structures

Added 6 new create context wire-format structures for the Fruit extension:

| Struct | Purpose |
|--------|---------|
| `create_fruit_server_query_req/rsp` | Server capability queries |
| `create_fruit_volume_caps_req/rsp` | Volume capability discovery |
| `create_fruit_file_mode_req/rsp` | UNIX file mode exchange |
| `create_fruit_dir_hardlinks_req/rsp` | Directory hardlink info |
| `create_fruit_rsp` | **Main AAPL response** — variable-length with `server_caps`, `volume_caps`, `model_string_len`, and `model[]` flexible array member (UTF-16LE) |

The `create_fruit_rsp` struct is the critical wire format:

```c
struct create_fruit_rsp {
    struct create_context ccontext;
    __u8   Name[4];          /* "AAPL" on wire */
    __le32 command_code;     /* 1 = kAAPL_SERVER_QUERY */
    __le32 reserved;
    __le64 reply_bitmap;     /* 0x07 = caps + volcaps + model */
    __le64 server_caps;      /* kAAPL_* capability bits */
    __le64 volume_caps;      /* kAAPL_SUPPORT_* volume bits */
    __le32 model_string_len; /* UTF-16LE byte count */
    __le16 model[];          /* variable-length UTF-16LE */
} __packed;
```

---

### 2.6 `smb2pdu.c` — Protocol Processing (largest change)

#### AAPL Create Context Negotiation (lines ~3710-3790)

**Before (upstream):** When an AAPL create context was found, the upstream code simply set `conn->is_aapl = true` and did nothing else. No capability negotiation, no state tracking, no response.

**After:** Full AAPL negotiation flow:
1. Gated by `KSMBD_GLOBAL_FLAG_FRUIT_EXTENSIONS` — admin must explicitly enable
2. Validates the create context structure (name length, data length)
3. Parses `fruit_client_info` (signature, version, client type, capabilities)
4. Calls `fruit_negotiate_capabilities()` to compute server capabilities from config flags
5. Allocates and populates `fruit_conn_state` on the connection
6. Sets `conn->is_fruit = true` and `fruit_ctxt = 1` to trigger response generation
7. On subsequent requests for already-negotiated connections, skips re-negotiation

#### AAPL Create Context Response (lines ~3945-3967)

**New code** chains the AAPL response into the SMB2 CREATE response:
- Calls `create_fruit_rsp_buf()` to build the variable-length response
- Dynamically computes response size (no static `create_fruit_size`)
- Properly chains the create context after POSIX contexts via `Next` pointers

#### ReadDirAttr UNIX Mode Enrichment (lines ~4234, ~4259)

For Fruit connections, calls `smb2_read_dir_attr_fill()` on each directory entry to pack UNIX mode bits into the `EaSize` field. This is the minimum viable ReadDirAttr that eliminates per-file QUERY_INFO round-trips from macOS Finder.

#### UniqueId Zero-FileID Gating (lines ~4238, ~4262)

**Before:** `if (conn->is_aapl) dinfo->UniqueId = 0;` — unconditionally zeroed for all Apple connections.

**After:** `if (conn->is_fruit && (server_conf.flags & KSMBD_GLOBAL_FLAG_FRUIT_ZERO_FILEID))` — gated by the admin-configurable `FRUIT_ZERO_FILEID` flag.

#### F_FULLFSYNC in SMB2 FLUSH (lines ~7754-7774)

**New code** detects Apple Time Machine's F_FULLFSYNC signal:
```c
if (conn->is_fruit && le16_to_cpu(req->Reserved1) == 0xFFFF)
    fullsync = true;
```
Passes `fullsync=true` to `ksmbd_vfs_fsync()` to trigger a physical device cache flush.

---

### 2.7 `oplock.c` / `oplock.h` — AAPL Response Builder

Added `create_fruit_rsp_buf()` (81 lines) — builds the complete variable-length AAPL create context response:

- Computes `server_caps` from global config flags (`kAAPL_UNIX_BASED` always, plus `kAAPL_SUPPORTS_OSX_COPYFILE` and `kAAPL_SUPPORTS_NFS_ACE` if configured)
- Sets `volume_caps` to `kAAPL_CASE_SENSITIVE | kAAPL_SUPPORTS_FULL_SYNC`
- Converts ASCII model string to UTF-16LE
- Returns dynamic size via `out_size` parameter

Also added `fruit_rsp_size()` inline helper for computing variable-length response sizes.

**Signature:** `int create_fruit_rsp_buf(char *cc, struct ksmbd_conn *conn, size_t *out_size)`

---

### 2.8 `vfs.c` / `vfs.h` — F_FULLFSYNC Implementation

**Signature change:**
```diff
-int ksmbd_vfs_fsync(struct ksmbd_work *work, u64 fid, u64 p_id);
+int ksmbd_vfs_fsync(struct ksmbd_work *work, u64 fid, u64 p_id, bool fullsync);
```

**New behavior:** When `fullsync=true`, after the normal `vfs_fsync()` succeeds, calls `blkdev_issue_flush()` on the underlying block device. This flushes the hardware write cache, matching macOS `F_FULLFSYNC` semantics. Required for Time Machine backup integrity on power loss.

Added `#include <linux/blkdev.h>` for `blkdev_issue_flush()`.

> **Note:** Upstream has modified `vfs.c` since our fork point (VFS
> delegation improvements, `vfs_create()` argument cleanup). A rebase
> will require resolving conflicts in this file.

---

### 2.9 `vfs_cache.c` — Updated fsync Caller

Updated `ksmbd_file_table_flush()` to pass `false` for the new `fullsync` parameter (table-wide flush doesn't need device-level flush).

> **Note:** Upstream has significantly modified `vfs_cache.c` since our
> fork point (race condition fix on `m_flags`, refactored file lifecycle).
> This will need careful conflict resolution during rebase.

---

### 2.10 `smb1pdu.c` — Updated fsync Caller

Updated `smb_flush()` to pass `false` for the new `fullsync` parameter (SMB1 has no F_FULLFSYNC signaling).

---

### 2.11 `mgmt/share_config.c` / `mgmt/share_config.h` — Time Machine Config

- Added `unsigned long long time_machine_max_size` to `struct ksmbd_share_config`
- `share_config_request()`: Copies `resp->time_machine_max_size` from the userspace-provided share configuration

---

### 2.12 `smbacl.c` — Comment Update

Updated comment from "Apple style" to "Fruit style" for consistency with the renamed extension (cosmetic only, no behavioral change).

---

### 2.13 `Makefile` — Build System

Added `smb2fruit.o` to the ksmbd module object list:
```diff
-  ksmbd_spnego_negtokentarg.asn1.o asn1.o compat.o
+  ksmbd_spnego_negtokentarg.asn1.o asn1.o compat.o smb2fruit.o
```

---

## 3. Wire Protocol Details

### 3.1 kAAPL Server Capabilities (`server_caps`)

These are the bit values sent in the `server_caps` field of the AAPL create context response. They match Apple's wire protocol exactly:

| Constant | Value | Meaning | Config Flag |
|----------|-------|---------|-------------|
| `kAAPL_SUPPORTS_READ_DIR_ATTR` | `0x01` | ReadDirAttr enrichment in directory listings | Always enabled |
| `kAAPL_SUPPORTS_OSX_COPYFILE` | `0x02` | Server-side file copy with metadata | `FRUIT_COPYFILE` |
| `kAAPL_UNIX_BASED` | `0x04` | Server is UNIX-based (enables UNIX mode display) | Always enabled |
| `kAAPL_SUPPORTS_NFS_ACE` | `0x08` | NFS ACE support in security descriptors | `FRUIT_NFS_ACES` |

### 3.2 kAAPL Volume Capabilities (`volume_caps`)

| Constant | Value | Meaning |
|----------|-------|---------|
| `kAAPL_SUPPORT_RESOLVE_ID` | `0x01` | File ID -> path resolution (not yet implemented) |
| `kAAPL_CASE_SENSITIVE` | `0x02` | Volume is case-sensitive |
| `kAAPL_SUPPORTS_FULL_SYNC` | `0x04` | Volume supports F_FULLFSYNC |

### 3.3 AAPL Create Context Response Wire Format

```
Offset  Size  Field
------  ----  -----
0       4     Next (create_context chain)
4       2     NameOffset
6       2     NameLength (= 4)
8       2     Reserved
10      2     DataOffset
12      4     DataLength
16      4     Name = "AAPL"
20      4     command_code = 1 (kAAPL_SERVER_QUERY)
24      4     reserved = 0
28      8     reply_bitmap = 0x07
36      8     server_caps (kAAPL_* bits)
44      8     volume_caps (kAAPL_SUPPORT_* bits)
52      4     model_string_len (UTF-16LE byte count)
56      var   model[] (UTF-16LE, no NUL terminator)
```

Total size = 56 + (model ASCII length x 2) bytes.

### 3.4 F_FULLFSYNC Detection

macOS Time Machine signals a full device cache flush by setting the `Reserved1` field of the SMB2 FLUSH request to `0xFFFF`. This is a private Apple extension not documented in MS-SMB2. When detected on a Fruit connection, ksmbd calls `blkdev_issue_flush()` on the underlying block device.

### 3.5 ReadDirAttr UNIX Mode Enrichment

When `kAAPL_SUPPORTS_READ_DIR_ATTR` is negotiated, the `EaSize` field of `FILE_ID_FULL_DIRECTORY_INFORMATION` and `FILE_ID_BOTH_DIRECTORY_INFORMATION` entries is repurposed to carry the UNIX mode bits (`S_IFMT | permission_bits`). This allows macOS Finder to display UNIX permissions without making per-file QUERY_INFO calls.

---

## 4. Configuration Interface

### 4.1 Global Settings (via ksmbd.mountd / ksmbd.conf)

| Setting | Flag | Default | Description |
|---------|------|---------|-------------|
| `fruit extensions` | `FRUIT_EXTENSIONS` | off | Master switch for AAPL protocol |
| `fruit zero fileid` | `FRUIT_ZERO_FILEID` | off | Zero UniqueId in directory listings |
| `fruit nfs aces` | `FRUIT_NFS_ACES` | off | Advertise NFS ACE support to macOS |
| `fruit copyfile` | `FRUIT_COPYFILE` | off | Advertise server-side copy support |
| `fruit model` | (string field) | "" | Server model string (e.g., "Xserve") |

### 4.2 Per-Share Settings (via ksmbd.conf share sections)

| Setting | Flag | Default | Description |
|---------|------|---------|-------------|
| `fruit time machine` | `FRUIT_TIME_MACHINE` | off | Mark share as Time Machine target |
| `fruit finder info` | `FRUIT_FINDER_INFO` | off | Enable FinderInfo enrichment (future) |
| `fruit rfork size` | `FRUIT_RFORK_SIZE` | off | Enable resource fork size reporting (future) |
| `fruit max access` | `FRUIT_MAX_ACCESS` | off | Enable max access rights reporting (future) |
| `time machine max size` | (u64 field) | 0 | Maximum Time Machine backup size in bytes |

> **Note:** The per-share flags `FRUIT_FINDER_INFO`, `FRUIT_RFORK_SIZE`, and
> `FRUIT_MAX_ACCESS` are structurally plumbed through the IPC interface but
> their kernel-side behavior is not yet implemented. See `MAXXPLAN.md` for
> the deferred implementation plan.

---

## 5. Userspace Changes Required (ksmbd-tools)

The following changes must be made to
[namjaejeon/ksmbd-tools](https://github.com/namjaejeon/ksmbd-tools)
to support the new kernel features. The current ksmbd-tools (v3.5.6)
has **zero** fruit/AAPL support — all changes below are new.

### 5.1 Shared Netlink Header: `include/linux/ksmbd_server.h`

This file must be kept in sync with the kernel's `ksmbd_netlink.h`.
The following changes are needed:

**Add 4 global config flags** (after `KSMBD_GLOBAL_FLAG_DURABLE_HANDLES`):

```c
#define KSMBD_GLOBAL_FLAG_FRUIT_EXTENSIONS    (1 << 5)
#define KSMBD_GLOBAL_FLAG_FRUIT_ZERO_FILEID   (1 << 6)
#define KSMBD_GLOBAL_FLAG_FRUIT_NFS_ACES      (1 << 7)
#define KSMBD_GLOBAL_FLAG_FRUIT_COPYFILE      (1 << 8)
```

**Add 4 per-share config flags** (after `KSMBD_SHARE_FLAG_CROSSMNT`):

```c
#define KSMBD_SHARE_FLAG_CONTINUOUS_AVAILABILITY  (1 << 16)
#define KSMBD_SHARE_FLAG_FRUIT_TIME_MACHINE       (1 << 17)
#define KSMBD_SHARE_FLAG_FRUIT_FINDER_INFO        (1 << 18)
#define KSMBD_SHARE_FLAG_FRUIT_RFORK_SIZE         (1 << 19)
#define KSMBD_SHARE_FLAG_FRUIT_MAX_ACCESS         (1 << 20)
```

**Modify `struct ksmbd_startup_request`** — carve `fruit_model` from reserved:

```diff
   __u32   max_ip_connections;
-  __s8    reserved[499];
+  __s8    fruit_model[64];
+  __s8    reserved[435];
   __u32   ifc_list_sz;
```

**Modify `struct ksmbd_share_config_response`** — carve `time_machine_max_size`:

```diff
   __s8    share_name[KSMBD_REQ_MAX_SHARE_NAME];
-  __u32   reserved[111];
+  __u64   time_machine_max_size;
+  __u32   reserved[109];
   __u32   payload_sz;
```

---

### 5.2 Global Config: `include/tools.h`

Add a `fruit_model` field to `struct smbconf_global`:

```diff
 struct smbconf_global {
     int         flags;
     ...
     unsigned int    max_ip_connections;
+    char            *fruit_model;
     unsigned int    share_fake_fscaps;
```

---

### 5.3 Global Config Parser: `tools/config_parser.c`

Add parsing for the 5 new global parameters in `process_global_conf_kv()`.
Insert after the `durable handles` block (~line 553):

```c
	if (group_kv_steal(kv, "fruit extensions", &k, &v)) {
		if (cp_get_group_kv_bool(v))
			global_conf.flags |=
				KSMBD_GLOBAL_FLAG_FRUIT_EXTENSIONS;
		else
			global_conf.flags &=
				~KSMBD_GLOBAL_FLAG_FRUIT_EXTENSIONS;
	}

	if (group_kv_steal(kv, "fruit zero fileid", &k, &v)) {
		if (cp_get_group_kv_bool(v))
			global_conf.flags |=
				KSMBD_GLOBAL_FLAG_FRUIT_ZERO_FILEID;
		else
			global_conf.flags &=
				~KSMBD_GLOBAL_FLAG_FRUIT_ZERO_FILEID;
	}

	if (group_kv_steal(kv, "fruit nfs aces", &k, &v)) {
		if (cp_get_group_kv_bool(v))
			global_conf.flags |=
				KSMBD_GLOBAL_FLAG_FRUIT_NFS_ACES;
		else
			global_conf.flags &=
				~KSMBD_GLOBAL_FLAG_FRUIT_NFS_ACES;
	}

	if (group_kv_steal(kv, "fruit copyfile", &k, &v)) {
		if (cp_get_group_kv_bool(v))
			global_conf.flags |=
				KSMBD_GLOBAL_FLAG_FRUIT_COPYFILE;
		else
			global_conf.flags &=
				~KSMBD_GLOBAL_FLAG_FRUIT_COPYFILE;
	}

	if (group_kv_steal(kv, "fruit model", &k, &v)) {
		global_conf.fruit_model = cp_get_group_kv_string(v);
	}
```

---

### 5.4 Share Config Enum: `include/management/share.h`

Add 5 new entries to `enum KSMBD_SHARE_CONF` (before `KSMBD_SHARE_CONF_MAX`):

```diff
     KSMBD_SHARE_CONF_CROSSMNT          = 30,
+    KSMBD_SHARE_CONF_FRUIT_TIME_MACHINE,
+    KSMBD_SHARE_CONF_FRUIT_FINDER_INFO,
+    KSMBD_SHARE_CONF_FRUIT_RFORK_SIZE,
+    KSMBD_SHARE_CONF_FRUIT_MAX_ACCESS,
+    KSMBD_SHARE_CONF_TIME_MACHINE_MAX_SIZE  = 35,
     KSMBD_SHARE_CONF_MAX
 };
```

Add `time_machine_max_size` to `struct ksmbd_share` (in `share.h`):

```diff
     unsigned short  force_gid;
+    unsigned long long  time_machine_max_size;
     char            *veto_list;
```

---

### 5.5 Share Config String Array: `tools/management/share.c`

Add the config key string mappings to the `KSMBD_SHARE_CONF[]` array (~line 31):

```diff
     [KSMBD_SHARE_CONF_CROSSMNT]           = "crossmnt",
+    [KSMBD_SHARE_CONF_FRUIT_TIME_MACHINE] = "fruit time machine",
+    [KSMBD_SHARE_CONF_FRUIT_FINDER_INFO]  = "fruit finder info",
+    [KSMBD_SHARE_CONF_FRUIT_RFORK_SIZE]   = "fruit rfork size",
+    [KSMBD_SHARE_CONF_FRUIT_MAX_ACCESS]   = "fruit max access",
+    [KSMBD_SHARE_CONF_TIME_MACHINE_MAX_SIZE] = "time machine max size",
```

And add corresponding defaults to the `KSMBD_SHARE_DEFCONF[]` array:

```diff
     [KSMBD_SHARE_CONF_CROSSMNT]           = "no",
+    [KSMBD_SHARE_CONF_FRUIT_TIME_MACHINE] = "no",
+    [KSMBD_SHARE_CONF_FRUIT_FINDER_INFO]  = "no",
+    [KSMBD_SHARE_CONF_FRUIT_RFORK_SIZE]   = "no",
+    [KSMBD_SHARE_CONF_FRUIT_MAX_ACCESS]   = "no",
+    [KSMBD_SHARE_CONF_TIME_MACHINE_MAX_SIZE] = "0",
```

---

### 5.6 Share Config Parser: `tools/management/share.c`

Add parsing for the 5 new share parameters in `process_share_conf_kv()`
(after the `crossmnt` block, ~line 760):

```c
	if (group_kv_steal(kv, KSMBD_SHARE_CONF_FRUIT_TIME_MACHINE, &k, &v)) {
		if (cp_get_group_kv_bool(v))
			set_share_flag(share, KSMBD_SHARE_FLAG_FRUIT_TIME_MACHINE);
		else
			clear_share_flag(share, KSMBD_SHARE_FLAG_FRUIT_TIME_MACHINE);
	}

	if (group_kv_steal(kv, KSMBD_SHARE_CONF_FRUIT_FINDER_INFO, &k, &v)) {
		if (cp_get_group_kv_bool(v))
			set_share_flag(share, KSMBD_SHARE_FLAG_FRUIT_FINDER_INFO);
		else
			clear_share_flag(share, KSMBD_SHARE_FLAG_FRUIT_FINDER_INFO);
	}

	if (group_kv_steal(kv, KSMBD_SHARE_CONF_FRUIT_RFORK_SIZE, &k, &v)) {
		if (cp_get_group_kv_bool(v))
			set_share_flag(share, KSMBD_SHARE_FLAG_FRUIT_RFORK_SIZE);
		else
			clear_share_flag(share, KSMBD_SHARE_FLAG_FRUIT_RFORK_SIZE);
	}

	if (group_kv_steal(kv, KSMBD_SHARE_CONF_FRUIT_MAX_ACCESS, &k, &v)) {
		if (cp_get_group_kv_bool(v))
			set_share_flag(share, KSMBD_SHARE_FLAG_FRUIT_MAX_ACCESS);
		else
			clear_share_flag(share, KSMBD_SHARE_FLAG_FRUIT_MAX_ACCESS);
	}

	if (group_kv_steal(kv, KSMBD_SHARE_CONF_TIME_MACHINE_MAX_SIZE, &k, &v)) {
		share->time_machine_max_size = cp_memparse(v);
	}
```

---

### 5.7 IPC Startup: `mountd/ipc.c`

In `ipc_ksmbd_starting_up()` (~line 150), add the `fruit_model` copy:

```diff
     ev->max_ip_connections = global_conf.max_ip_connections;
+    if (global_conf.fruit_model) {
+        strncpy(ev->fruit_model,
+                global_conf.fruit_model,
+                sizeof(ev->fruit_model) - 1);
+    }
     ev->share_fake_fscaps = global_conf.share_fake_fscaps;
```

---

### 5.8 IPC Share Config Response: `tools/management/share.c`

In `shm_handle_share_config_request()` (~line 938), add the Time Machine
size copy:

```diff
     resp->force_gid = share->force_gid;
+    resp->time_machine_max_size = share->time_machine_max_size;
     *resp->share_name = 0x00;
```

---

### 5.9 Config Example: `ksmbd.conf.example`

Add the new parameters to the example config:

```ini
[global]
    ; ... existing parameters ...
    fruit extensions = no
    fruit zero fileid = no
    fruit nfs aces = no
    fruit copyfile = no
    fruit model =

[TimeMachine]
    comment = Time Machine Backup
    path = /srv/timemachine
    read only = no
    guest ok = no
    fruit time machine = yes
    time machine max size = 500G
```

---

### 5.10 Man Page: `ksmbd.conf.5.in`

Document all 10 new parameters. Fruit global parameters should be
grouped under an "Apple/macOS Compatibility" subsection. Per-share
fruit parameters should explain their relationship to macOS features:

- `fruit extensions` (boolean, default no) — enables the Apple AAPL SMB
  create context protocol. Required for all other fruit features.
- `fruit zero fileid` (boolean, default no) — zeroes the UniqueId field
  in directory listings. Required by some macOS applications.
- `fruit nfs aces` (boolean, default no) — advertises NFS ACE support
  to macOS clients.
- `fruit copyfile` (boolean, default no) — advertises server-side file
  copy support to macOS clients.
- `fruit model` (string, default empty) — server model string shown in
  macOS Finder's "Get Info" dialog. Examples: "MacSamba", "Xserve".
- `fruit time machine` (boolean, default no) — marks the share as a
  valid Time Machine backup destination.
- `fruit finder info` (boolean, default no) — reserved for future
  FinderInfo enrichment in directory listings.
- `fruit rfork size` (boolean, default no) — reserved for future
  resource fork size reporting in directory listings.
- `fruit max access` (boolean, default no) — reserved for future
  max access rights reporting in directory listings.
- `time machine max size` (size, default 0) — maximum backup size for
  Time Machine in bytes. Supports K/M/G/T suffixes. 0 = unlimited.

---

### 5.11 ksmbd-tools Summary of Changes

| File | Change |
|------|--------|
| `include/linux/ksmbd_server.h` | Sync with kernel: 4 global flags, 4 share flags, fruit_model field, time_machine_max_size field |
| `include/tools.h` | Add `fruit_model` to `smbconf_global` |
| `include/management/share.h` | Add 5 entries to `KSMBD_SHARE_CONF` enum, add `time_machine_max_size` to share struct |
| `tools/config_parser.c` | Parse 5 new global parameters in `process_global_conf_kv()` |
| `tools/management/share.c` | Add 5 config key strings, parse 5 share parameters, copy `time_machine_max_size` in IPC response |
| `mountd/ipc.c` | Copy `fruit_model` in `ipc_ksmbd_starting_up()` |
| `ksmbd.conf.example` | Add all 10 new parameters with defaults |
| `ksmbd.conf.5.in` | Document all 10 new parameters |

---

## 6. Upstream Divergence

### 6.1 Upstream Changes Since Fork Point

Upstream ([namjaejeon/ksmbd](https://github.com/namjaejeon/ksmbd))
has advanced from commit `f012374` (v3.5.3) to v3.5.4 with ~20 commits.
Key upstream changes:

| Commit | File(s) | Description |
|--------|---------|-------------|
| `a1a1a42` | — | Release 3.5.4 version tag |
| `71e3b5f` | `transport_ipc.c` | Fix use-after-free in `ipc_msg_send_request` |
| `78aab9a` | `vfs_cache.c` | Fix race on `m_flags` |
| `54b75a0` | `misc.c` | Replace strcpy + strcat for `convert_to_nt_pathname` |
| `2605a96` | `smb2pdu.c` | Error handling for STATUS_INFO_LENGTH_MISMATCH |
| `c21b694` | `mgmt/tree_connect.c` | Fix use-after-free in `ksmbd_tree_connect_put` |
| `a828fc3` | `connection.c` | Avoid busy polling in accept loop |
| `75755d6` | `smb2pdu.c` | Skip lock-range check on equal size |
| Various | `smb2pdu.c` | Fix return values of smb2_oplock_break, smb2_ioctl, smb2_query_dir, smb2_notify, smb2_read |
| VFS | `vfs.c`, `vfs.h` | vfs_create delegation break improvements, argument cleanup |
| `ff4dea7` | `connection.c` | Close socket when per-IP limit rejects |
| `817ca98` | `transport_tcp.c` | Convert proto_ops bind() to sockaddr_unsized |
| RDMA | `transport_rdma.c/.h` | Major RDMA refactoring (+280/-140 lines) |

### 6.2 Files Changed by Both (Merge Conflict Risk)

| File | Our Change | Upstream Change | Risk |
|------|-----------|-----------------|------|
| `smb2pdu.c` | +97 lines (AAPL negotiation, F_FULLFSYNC) | Multiple return value fixes, lock-range fix | **Medium** — different functions, but context shifts |
| `vfs.c` | +20 lines (fullsync parameter) | vfs_create refactoring, delegation breaks | **Medium** — overlapping area |
| `vfs.h` | +1 line (fsync signature) | vfs_create signature change | **Low** — different functions |
| `vfs_cache.c` | +1 line (fsync caller) | Race fix on m_flags, refactoring | **Low** — different code paths |
| `connection.c` | +9 lines (fruit_state cleanup) | Accept loop fix, socket close | **Low** — different functions |
| `transport_ipc.c` | +2 lines (fruit_model copy) | Use-after-free fix | **Low** — different functions |

### 6.3 Rebase Strategy

1. Fetch upstream: `git fetch upstream`
2. Rebase onto upstream/master: `git rebase upstream/master`
3. Resolve conflicts file by file (expect 2-3 manual resolutions)
4. Rebuild and run tests: `make clean && make && ./test_framework/run_fruit_tests`
5. Force-push the rebased branch

---

## 7. Test Coverage

### 7.1 Primary Test Suite: `run_fruit_tests.c`

**103 tests** across 26 groups (A-Z):

| Group | Tests | What It Covers |
|-------|-------|----------------|
| A | 3 | `fruit_valid_signature()` — AAPL signature validation |
| B | 4 | `fruit_validate_create_context()` — create context structure checks |
| C | 5 | `fruit_parse_client_info()` — client info parsing, NULL safety |
| D | 4 | `fruit_detect_client_version()` — version detection, bad signatures |
| E | 6 | `fruit_get_client_name()` — macOS/iOS/iPadOS/tvOS/watchOS mapping |
| F | 4 | `fruit_get_version_string()` — version string mapping |
| G | 3 | `fruit_init_connection_state()` — state initialization from config |
| H | 2 | `fruit_cleanup_connection_state()` — state zeroing, NULL safety |
| I | 5 | `fruit_negotiate_capabilities()` — server caps from config, NULL safety, extensions_enabled |
| J | 3 | `fruit_supports_capability()` — bitwise capability checks |
| K | 4 | `fruit_update_connection_state()` — client/server cap intersection |
| L | 8 | `fruit_get_context_size()` — all 6 context types + NULL + unknown |
| M | 3 | `fruit_build_server_response()` — response allocation, NULL safety |
| N | 2 | `fruit_debug_client_info()` — debug output, NULL safety |
| O | 1 | `fruit_debug_capabilities()` — kAAPL bit debug output |
| P | 3 | `fruit_process_looker_info()` — FinderInfo processing |
| Q | 7 | savebox/server_query/read_dir_attr/handle_bundle — NULL safety |
| R | 3 | `create_fruit_rsp_buf()` — full AAPL response wire format validation |
| S | 3 | Struct layout verification (field offsets, sizes) |
| T | 2 | kAAPL wire protocol constant values, AAPL tag string |
| U | 3 | `fruit_is_client_request()` — request detection, short buffers |
| V | 2 | Module init/cleanup lifecycle |
| W | 6 | Config flag bit positions, uniqueness, no collisions |
| X | 6 | Config flag set/clear operations, model string, Time Machine size |
| Y | 6 | kAAPL server/volume cap constants, AFP stream constants, ReadDirAttr |
| Z | 5 | F_FULLFSYNC Reserved1 detection, ReadDirAttr mode packing (fruit/non-fruit/NULL) |

**Build command:**
```bash
gcc -I test_framework/include -I . -o test_framework/run_fruit_tests \
    test_framework/run_fruit_tests.c
./test_framework/run_fruit_tests
```

### 7.2 Build Verification

```bash
make clean && make    # Zero errors, zero warnings
```

---

## 8. Architecture Decisions

### 8.1 Why Separate `smb2fruit.c` Instead of Inline in `smb2pdu.c`

The Fruit extension is a self-contained protocol negotiation layer. Keeping it in its own compilation unit:
- Allows the extension to be conditionally compiled (future `CONFIG_SMB_FRUIT` Kconfig option)
- Keeps `smb2pdu.c` (already 8000+ lines) from growing further
- Isolates Apple-specific protocol knowledge from generic SMB2 processing
- Enables userspace unit testing via direct `#include` of the `.c` file

### 8.2 Why Config-Driven Capabilities Instead of Client Intersection

The upstream code had `conn->is_aapl = true` as a bare boolean with no capability negotiation. Our implementation computes `server_caps` from admin-configured flags rather than intersecting with client-advertised capabilities. Rationale:

- The server knows what it actually supports — client claims are informational
- Admin control over what gets advertised prevents feature creep
- Matches Samba's `vfs_fruit` design where server capabilities are config-driven
- kAAPL server_caps are server-declared, not negotiated (unlike SMB2 dialects)

### 8.3 Why Variable-Length AAPL Response

Apple's wire protocol defines `reply_bitmap=0x07` as: bit 0 = server_caps, bit 1 = volume_caps, bit 2 = model_info. The upstream had no response at all. A fixed-size struct would either waste space (fixed model buffer) or limit model string length. The flexible array member approach matches the wire format exactly and allows arbitrary model strings.

### 8.4 Why `blkdev_issue_flush()` for F_FULLFSYNC

macOS `F_FULLFSYNC` means "flush to physical media, not just filesystem journal." Linux's `vfs_fsync()` only guarantees filesystem-level consistency. `blkdev_issue_flush()` issues a cache flush command to the block device, matching the macOS semantic. This is critical for Time Machine — without it, backups can be silently corrupted if power is lost between `vfs_fsync()` returning and the data hitting platters.

---

## 9. File-by-File Diff Summary

### New Files (kernel)

| File | Lines | Status |
|------|-------|--------|
| `smb2fruit.h` | 214 | New |
| `smb2fruit.c` | 395 | New |

### Modified Files (kernel)

| File | +/- | Change Summary |
|------|-----|----------------|
| `ksmbd_netlink.h` | +14 | 4 global flags, 4 share flags, fruit_model field, time_machine_max_size field |
| `connection.h` | +6 | `is_aapl` -> `is_fruit`, `fruit_state` pointer |
| `connection.c` | +9 | fruit_state cleanup in `ksmbd_conn_free()` |
| `server.h` | +1 | `fruit_model[64]` in server config |
| `server.c` | +7 | fruit_init_module/fruit_cleanup_module calls |
| `transport_ipc.c` | +2 | Copy fruit_model from startup request |
| `smb2pdu.h` | +70 | 6 create context structs + create_fruit_rsp |
| `smb2pdu.c` | +97/-6 | AAPL negotiation, response chaining, ReadDirAttr, UniqueId gating, F_FULLFSYNC |
| `oplock.c` | +77 | `create_fruit_rsp_buf()` implementation |
| `oplock.h` | +1 | `create_fruit_rsp_buf()` declaration |
| `vfs.c` | +20/-1 | fullsync parameter + `blkdev_issue_flush()` |
| `vfs.h` | +1/-1 | Updated `ksmbd_vfs_fsync()` signature |
| `vfs_cache.c` | +1/-1 | Updated fsync caller |
| `smb1pdu.c` | +1/-1 | Updated fsync caller |
| `mgmt/share_config.c` | +1 | Copy `time_machine_max_size` |
| `mgmt/share_config.h` | +1 | `time_machine_max_size` field |
| `smbacl.c` | +1/-1 | Comment update (cosmetic) |
| `Makefile` | +1/-1 | Add `smb2fruit.o` to build |

### New Files (test framework)

| File | Lines | Status |
|------|-------|--------|
| `test_framework/run_fruit_tests.c` | 1,433 | New (primary test runner, 103 tests) |
| `test_framework/test_utils.h` | 382 | New |
| `test_framework/unit_test_framework.c` | 447 | New |
| `test_framework/apple_enhanced_unit_tests.c` | 879 | New |
| `test_framework/apple_security_tests.c` | 954 | New |
| `test_framework/apple_smb_real_client_testing.c` | 1,034 | New |
| `test_framework/integration_compatibility_testing.c` | 1,095 | New |
| `test_framework/integration_test_framework.c` | 707 | New |
| `test_framework/performance_test_framework.c` | 919 | New |
| `test_framework/production_readiness_validation.c` | 1,050 | New |
| `test_framework/smb2_end_to_end_testing.c` | 1,139 | New |
| `test_framework/include/linux/slab.h` | ~30 | New (userspace stub) |

---

## 10. Known Limitations

1. **AAPL response is always sent** when `FRUIT_EXTENSIONS` is enabled — there is no per-share gating of the AAPL negotiation itself (only the subsequent features are per-share gated).

2. **ReadDirAttr only packs UNIX mode** — full FinderInfo (32 bytes), resource fork size, and max access rights are not yet injected. See `MAXXPLAN.md` items 4 and 6.

3. **AFP_AfpInfo stream interception is not implemented** — the constants are defined but the VFS read/write interception for FinderInfo xattr synthesis is deferred. See `MAXXPLAN.md` item 6.

4. **Time Machine xattr synthesis is not implemented** — the config plumbing exists (`FRUIT_TIME_MACHINE` flag, `time_machine_max_size` field) but the kernel does not yet synthesize `com.apple.timemachine.supported` xattrs. See `MAXXPLAN.md` item 7.

5. **kAAPL_SUPPORT_RESOLVE_ID is not set** in volume_caps — file ID resolution requires IOCTL support that is not yet implemented. See `MAXXPLAN.md` item 3.

6. **Model string conversion is ASCII-only** — the UTF-16LE conversion in `create_fruit_rsp_buf()` assumes ASCII model strings. Non-ASCII model names would need proper UTF-8 -> UTF-16LE conversion.

7. **Per-share config flags** (`FRUIT_FINDER_INFO`, `FRUIT_RFORK_SIZE`, `FRUIT_MAX_ACCESS`) are plumbed through IPC but not checked in kernel code paths (structural preparation for future work).

---

## 11. Security Considerations

1. **Input validation:** All create context parsing validates `NameLength == 4`, `DataLength >= sizeof(fruit_client_info)`, and AAPL signature before processing.

2. **Memory safety:** `fruit_state` is allocated via `kzalloc` and freed in `ksmbd_conn_free()`. All functions check for NULL state pointers.

3. **No new attack surface beyond SMB2 CREATE:** The AAPL extension is negotiated within the existing SMB2 CREATE code path. No new IPC channels, IOCTLs, or system calls are added.

4. **Config-gated:** The entire extension is disabled by default. `KSMBD_GLOBAL_FLAG_FRUIT_EXTENSIONS` must be explicitly enabled by the administrator.

5. **F_FULLFSYNC bounds:** The `blkdev_issue_flush()` call is gated by `conn->is_fruit` AND `Reserved1 == 0xFFFF`. A non-Apple client cannot trigger device flushes via this path.

---

## 12. Compatibility Matrix

| macOS Feature | Status | Notes |
|---------------|--------|-------|
| Finder file browsing | Working | ReadDirAttr eliminates per-file queries |
| Finder icon display | Partial | UNIX mode packed; full FinderInfo deferred |
| Copy/paste files | Working | Standard SMB2 operations |
| Time Machine discovery | Config ready | Needs userspace Bonjour + xattr synthesis |
| Time Machine backup | Partial | F_FULLFSYNC works; xattr synthesis deferred |
| Spotlight search | Not implemented | Requires mdssvc RPC (see MAXXPLAN.md) |
| Aliases ("Show Original") | Not implemented | Requires RESOLVE_ID IOCTL |
| Server-side copy | Config ready | IOCTL handler not yet implemented |
| Persistent handles | Upstream | Existing ksmbd durable handle support |

---

## 13. How to Test

### Build kernel module
```bash
make clean && make
sudo make install
sudo modprobe ksmbd
```

### Run unit tests
```bash
gcc -I test_framework/include -I . \
    -o test_framework/run_fruit_tests \
    test_framework/run_fruit_tests.c
./test_framework/run_fruit_tests
# Expected: ALL 103 TESTS PASSED
```

### Configure for macOS clients
```ini
# /etc/ksmbd/ksmbd.conf
[global]
    fruit extensions = yes
    fruit nfs aces = yes
    fruit copyfile = yes
    fruit model = MacSamba

[Data]
    path = /srv/data
    fruit finder info = yes

[TimeMachine]
    path = /srv/timemachine
    fruit time machine = yes
    time machine max size = 500G
```

### Verify AAPL negotiation
```bash
sudo ksmbd.control -d "smb"
# Connect from macOS Finder, check dmesg for:
# "Fruit client: sig=AAPL ver=2.0 type=macOS caps=0x..."
```
