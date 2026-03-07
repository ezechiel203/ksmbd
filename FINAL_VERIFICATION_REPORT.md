# Final Verification Report of KSMBD Issues (2026-02-27)

This report summarizes the current status of the issues identified in previous reviews of the KSMBD kernel module and `ksmbd-tools`.

## 1. Verified Fixes

### 1.1 [CRITICAL] Binary Handle Collision in RPC (ksmbd-tools)
- **Status**: **FIXED**
- **Verification**: `ksmbd-tools/mountd/rpc_lsarpc.c` now implements `handle_hash` and `handle_equal` using `memcmp` and a byte-by-byte hash loop, and initializes `ph_table` with these functions.

### 1.2 [CRITICAL] Heap Buffer Overflow in `base64_decode` (ksmbd-tools)
- **Status**: **FIXED**
- **Verification**: `ksmbd-tools/tools/tools.c` now includes a `g_realloc(ret, *dstlen + 1)` call before writing the null terminator.

### 1.3 [HIGH] Use-After-Free in `tree_connect` (Kernel)
- **Status**: **FIXED**
- **Verification**: `src/mgmt/tree_connect.c` now calls `ksmbd_share_config_put()` inside `ksmbd_tree_connect_put()` only when the reference count reaches zero.

### 1.4 [HIGH] Preauth Session Table Race Condition (Kernel)
- **Status**: **FIXED** (via Call-site Locking)
- **Verification**: While the lookup helper itself is lockless, all observed call sites in `src/protocol/smb2/smb2_pdu_common.c` and `src/core/auth.c` now wrap the call in `down_read` or `down_write` of `conn->session_lock`.

### 1.5 [MEDIUM] Sensitive Signing Key Leak (Kernel)
- **Status**: **FIXED**
- **Verification**: `src/mgmt/user_session.c:261` now calls `memzero_explicit(chann->smb3signingkey, ...)` before freeing the channel.

### 1.6 [MEDIUM] Preauth Session Memory Leak (Kernel)
- **Status**: **FIXED**
- **Verification**: `src/core/connection.c:107` (approx) now includes a `list_for_each_entry_safe` loop to drain and free `conn->preauth_sess_table` during connection cleanup.

### 1.7 [MEDIUM] Endianness & Type Mismatches (Kernel)
- **Status**: **FIXED**
- **Verification**: `src/protocol/smb2/smb2_query_set.c:807` now uses `cpu_to_le16(COMPRESSION_FORMAT_LZNT1)`.

### 1.8 [MEDIUM] Kernel-Userspace IPC Payload Mismatch
- **Status**: **FIXED**
- **Verification**: both `src/include/transport/transport_ipc.h` and `ksmbd-tools/include/ipc.h` now define the maximum message/payload size as 4096.

---

## 2. Outstanding / Unfixed Issues

### 2.1 [HIGH] `SMB2_NEGOTIATE` Length Validation Bypass (Kernel)
- **Status**: **UNFIXED**
- **Details**: `src/protocol/smb2/smb2misc.c` still lacks a `case SMB2_NEGOTIATE` in `smb2_get_data_area_len()`, and the `ksmbd_smb2_check_message()` function still contains the unconditional `goto validate_credit` for negotiate commands.

### 2.2 [HIGH] Passwords Exposed in Memory and CLI (ksmbd-tools)
- **Status**: **UNFIXED**
- **Details**: Command-line passwords are still visible in `/proc/PID/cmdline`, and `usm_update_user_password` still calls `g_free()` on passwords without scrubbing.

### 2.3 [MEDIUM] Memory Safety Violation in `normalize_path` (Kernel)
- **Status**: **UNFIXED**
- **Details**: The compatibility branch of `normalize_path` in `src/core/misc.c` still performs in-place modification (`next[0] = '\0'`) of the input buffer, which can be a `const char *`.

### 2.4 [LOW] Missing `__packed` on Wire-Format Structs (ksmbd-tools)
- **Status**: **UNFIXED**
- **Details**: Headers in `ksmbd-tools/include/rpc.h` and `smbacl.h` still lack the `__packed` attribute on several protocol structures.

---
**Final Status**: The project has made significant progress in fixing memory safety and lifetime issues in the kernel, but several security-relevant validation and credential-handling gaps remain in the userspace tools and the SMB2 negotiate path.
