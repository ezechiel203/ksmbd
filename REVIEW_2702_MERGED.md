# KSMBD Full Merged Code Review Report (2026-02-27)

**Scope**: Comprehensive line-by-line review and synthesis of all static analysis, previous audits, and manual verification for KSMBD kernel module and `ksmbd-tools`.

## 1. Executive Summary
This report merges findings from multiple analysis passes, filtering out false positives (such as the previously suspected OOB read in `smb2_write` which is safely bounded by `smb2_calc_size` gatekeeping) and prioritizing true risks. The most severe issues reside in the `ksmbd-tools` userland daemon (buffer overflows, cryptographic mishandling, and handle hashing collisions) and kernel lifetime management (UAF in tree connections). 

## 2. Critical Severity Issues

### 2.1 [CRITICAL] Binary Handle Collision in RPC (ksmbd-tools)
- **Location**: `ksmbd-tools/mountd/rpc_lsarpc.c:737`, `ksmbd-tools/mountd/rpc_samr.c:1034`
- **Problem**: 20-byte binary RPC handles are used as keys in GLib hash tables using `g_str_hash` and `g_str_equal`.
- **Impact**: `g_str_hash` stops at the first null byte. Since handles often contain null bytes, multiple different handles will collide, leading to incorrect handle lookups and potential security bypasses in LSARPC/SAMR operations.
- **Fix**: Use `g_bytes_hash` and `g_bytes_equal` or implement a custom fixed-size 20-byte memory hash/compare function.

### 2.2 [CRITICAL] Heap Buffer Overflow in `base64_decode` (ksmbd-tools)
- **Location**: `ksmbd-tools/tools/tools.c:271`
- **Problem**: The wrapper `base64_decode` writes a null terminator `ret[*dstlen] = 0x00`, but `g_base64_decode` only allocates exactly `*dstlen` bytes.
- **Impact**: A 1-byte out-of-bounds heap write occurs on every base64 decode (e.g., parsing password hashes), which can corrupt heap metadata and lead to process compromise.
- **Fix**: Reallocate the buffer to `*dstlen + 1` before appending the null terminator, or avoid null termination for binary data.

## 3. High Severity Issues

### 3.1 [HIGH] Use-After-Free in `tree_connect` teardown (Kernel)
- **Location**: `src/mgmt/tree_connect.c:117, 173`
- **Problem**: `ksmbd_tree_conn_disconnect()` and `ksmbd_tree_conn_session_logoff()` call `ksmbd_share_config_put(tree_conn->share_conf)` before the final `tree_conn` reference is dropped.
- **Impact**: Other threads holding a reference to `tree_conn` might attempt to access `tree_conn->share_conf` after it has been freed, causing a kernel panic or exploitable memory corruption.
- **Fix**: Move `ksmbd_share_config_put()` into the final destructor path in `ksmbd_tree_connect_put()`.

### 3.2 [HIGH] `SMB2_NEGOTIATE` Length Validation Bypass (Kernel)
- **Location**: `src/protocol/smb2/smb2misc.c:460`
- **Problem**: `ksmbd_smb2_check_message()` explicitly bypasses length matching validation (`clc_len != len`) if the command is `SMB2_NEGOTIATE`. Furthermore, `smb2_get_data_area_len()` has no handler for negotiate, leaving the data area unvalidated. 
- **Impact**: Attackers can append arbitrary trailing garbage to `SMB2_NEGOTIATE` requests without rejection, bypassing the gatekeeper length validation.
- **Fix**: Implement a specific `case SMB2_NEGOTIATE_HE:` in `smb2_get_data_area_len()` to compute the variable data area correctly, and remove the blanket bypass in `ksmbd_smb2_check_message()`.

### 3.3 [HIGH] Passwords Exposed in Memory and CLI (ksmbd-tools)
- **Location**: `ksmbd-tools/adduser/adduser.c:91`, `tools/management/user.c:333`
- **Problem**: Passwords supplied via `-p` are kept in `argv` (visible in `/proc/PID/cmdline`). When freeing password buffers during updates, `g_free()` is called without a prior `explicit_bzero()`.
- **Impact**: Plaintext passwords remain in process memory and the system process list indefinitely.
- **Fix**: Scrub `argv` when parsing `-p`, and consistently use `explicit_bzero()` before freeing credential buffers.

### 3.4 [HIGH] Preauth Session Table Race Condition (Kernel)
- **Location**: `src/mgmt/user_session.c:424, 525`
- **Problem**: Operations on the `conn->preauth_sess_table` list lack synchronization (spinlocks or rwlocks).
- **Impact**: Concurrent SMB3 session setups (e.g. multi-channel) can corrupt the linked list, leading to kernel panics or double-frees.
- **Fix**: Protect `preauth_sess_table` mutations with `conn->session_lock` or a dedicated spinlock.

## 4. Medium Severity Issues

### 4.1 [MEDIUM] Sensitive Signing Key Leak in `ksmbd_chann_del` (Kernel)
- **Location**: `src/mgmt/user_session.c:261`
- **Problem**: The channel structure is freed using `kfree(chann)` without scrubbing `chann->smb3signingkey`.
- **Impact**: Cryptographic keys remain in the kernel heap after the channel is destroyed.
- **Fix**: Add `memzero_explicit(chann->smb3signingkey, sizeof(chann->smb3signingkey))` before freeing.

### 4.2 [MEDIUM] Preauth Session Memory Leak (Kernel)
- **Location**: `src/core/connection.c:98`
- **Problem**: `ksmbd_conn_cleanup()` does not iterate and free the elements in `conn->preauth_sess_table`.
- **Impact**: If a connection is closed before pre-authentication is finalized, the `preauth_session` allocations leak.
- **Fix**: Drain and `kfree_sensitive()` all entries in `preauth_sess_table` during connection cleanup.

### 4.3 [MEDIUM] Kernel-Userspace IPC Payload Mismatch
- **Location**: `ksmbd-tools/include/ipc.h` vs Kernel `src/include/transport/transport_ipc.h`
- **Problem**: The userspace daemon defines `KSMBD_IPC_MAX_MESSAGE_SIZE` as 64KB, but the kernel rejects messages strictly larger than 4096 bytes (`KSMBD_IPC_MAX_PAYLOAD`).
- **Impact**: If `ksmbd.mountd` attempts to send a large management response (e.g., share enumeration with many shares), the kernel silently rejects it, causing the operation to fail or timeout.
- **Fix**: Synchronize the maximum IPC payload constants between the kernel and the tools.

### 4.4 [MEDIUM] Endianness & Type Mismatches in Structures (Kernel)
- **Location**: `src/protocol/smb2/smb2_query_set.c:807`, `src/fs/ksmbd_fsctl.c`
- **Problem**: `__le16` fields (like `CompressionFormat`) are assigned host-endian literals without `cpu_to_le16()`, and `ResumeKey` assigns little-endian converted data to a `__u64` target instead of `__le64`.
- **Impact**: Potential bugs or failure to conform to the SMB protocol on Big-Endian architectures.
- **Fix**: Apply correct `cpu_to_le16()` / `cpu_to_le64()` macros and update struct definitions in `smb2pdu.h`.

### 4.5 [MEDIUM] Memory Safety Violation in `normalize_path` Compatibility Code
- **Location**: `src/core/misc.c:375` (older kernels `< 5.6.0`)
- **Problem**: `normalize_path` modifies the input pointer temporarily (`next[0] = '\0'`) to parse directories. When invoked via `convert_to_unix_name` with a `const char *`, it writes to the buffer.
- **Impact**: While the buffer is typically a heap-allocated request packet rather than read-only memory, modifying an active packet buffer in-place is unsafe and introduces data races if the packet is concurrently accessed.
- **Fix**: Allocate a temporary string copy before tokenizing, or use `strchr` length math instead of null-termination.

## 5. Low Severity / Code Quality Issues

### 5.1 [LOW] Context Imbalance Warning in Debugfs
- **Location**: `src/core/ksmbd_debugfs.c:91`
- **Problem**: Sparse static analysis flags a possible context imbalance. The loop uses `i = -1; break;` to restart scanning, which can confuse static analysis tools regarding lock/unlock parity.
- **Fix**: Refactor the retry loop using a cleaner `goto` or while loop to guarantee lock pairing is statically provable.

### 5.2 [LOW] Missing `__packed` on Wire-Format Structs (ksmbd-tools)
- **Location**: `ksmbd-tools/include/rpc.h`, `smbacl.h`
- **Problem**: Several network structs (e.g., `dcerpc_header`) are missing the `__packed` attribute, which could lead to compiler-inserted padding breaking protocol compatibility.
- **Fix**: Apply `__packed` to all structs representing over-the-wire layouts.
