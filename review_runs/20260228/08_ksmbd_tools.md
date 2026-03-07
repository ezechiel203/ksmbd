# Security Code Review: ksmbd-tools Userspace Daemon and Utilities

**Date:** 2026-02-28
**Reviewer:** Claude Opus 4.6 (Automated Security Review)
**Scope:** Complete ksmbd-tools userspace codebase
**Risk Context:** The `ksmbd.mountd` daemon runs as root, processes netlink messages from the kernel module, handles DCE/RPC requests from untrusted SMB clients, and manages authentication credentials. The CLI tools (`ksmbd.adduser`, `ksmbd.addshare`, `ksmbd.control`) also run with elevated privileges.

---

## Executive Summary

The ksmbd-tools codebase demonstrates a generally sound security posture for a root-running daemon. The developers have clearly invested effort in input validation, memory safety, and credential hygiene. Key strengths include: consistent use of `explicit_bzero` for password material, NUL-termination validation on all IPC string fields, overflow checks in NDR parsing, bounded message sizes, and a robust fork-based worker isolation model.

However, the review identified several issues across the severity spectrum. The most significant concerns involve: (1) use of the cryptographically broken MD4 algorithm for password hashing (protocol-mandated, but worth documenting), (2) an integer overflow in the ASN.1 tag decoder that could be triggered by crafted SPNEGO tokens, (3) predictable handle generation in the SAMR RPC service, (4) `abort()` calls in the daemon that could cause denial of service, and (5) missing overflow checks in the subauth configuration parser. The test suite, while present, has significant coverage gaps -- particularly for the RPC subsystem, SPNEGO/Kerberos, and the administrative tools.

**Overall Risk Rating: MEDIUM** -- No trivially exploitable remote code execution paths were identified, but several issues could enable denial-of-service or information disclosure when combined.

---

## Critical Findings (P0)

No critical (P0) findings were identified. The codebase does not contain trivially exploitable remote code execution vulnerabilities in the reviewed paths.

---

## High Findings (P1)

### P1-01: ASN.1 Tag Decoder Integer Overflow

**File:** `/home/ezechiel203/ksmbd/ksmbd-tools/tools/asn1.c`, lines 48-62
**Category:** Buffer Overflow / Integer Overflow
**CVSS Estimate:** 7.5 (Network/Low/None)

The `asn1_tag_decode()` function shifts `*tag` left by 7 bits in a loop without overflow protection:

```c
static unsigned char
asn1_tag_decode(struct asn1_ctx *ctx, unsigned int *tag)
{
    unsigned char ch;

    *tag = 0;

    do {
        if (!asn1_octet_decode(ctx, &ch))
            return 0;
        *tag <<= 7;       // No overflow check
        *tag |= ch & 0x7F;
    } while ((ch & 0x80) == 0x80);
    return 1;
}
```

A crafted SPNEGO token with a long-form tag containing 5 or more continuation bytes will cause `*tag` (an `unsigned int`, typically 32-bit) to overflow. Since the tag value is consumed by subsequent decoding logic, a controlled overflow could cause misinterpretation of ASN.1 structure boundaries, potentially leading to out-of-bounds reads during SPNEGO token parsing.

**Impact:** An unauthenticated remote attacker sending a crafted SMB session setup with a malicious SPNEGO blob could trigger this overflow during Kerberos authentication processing.

**Recommendation:** Add an iteration limit or overflow check:
```c
if (*tag > (UINT_MAX >> 7))
    return 0;  // would overflow
*tag <<= 7;
```

---

### P1-02: MD4 Password Hashing (Protocol-Mandated Weakness)

**File:** `/home/ezechiel203/ksmbd/ksmbd-tools/adduser/md4_hash.c`
**File:** `/home/ezechiel203/ksmbd/ksmbd-tools/adduser/user_admin.c`, line 145-158
**Category:** Password Handling / Weak Cryptography

The password database stores NTLM password hashes computed via MD4. The `process_password()` function converts passwords to UTF-16LE, then computes an MD4 hash, then base64-encodes the result for storage:

```c
static void __md4_hash(char **password, size_t *sz)
{
    struct md4_ctx mctx;
    md4_init(&mctx);
    md4_update(&mctx, (const unsigned char *)*password, *sz);
    explicit_bzero(*password, old_sz);
    g_free(*password);
    *sz = sizeof(mctx.hash) + 1;
    *password = g_malloc0(*sz);
    md4_final(&mctx, (unsigned char *)*password);
}
```

MD4 is cryptographically broken -- collisions can be found in milliseconds and preimage attacks are practical. While this is mandated by the NTLM protocol and cannot be changed without breaking compatibility, it means that if the password database file (`ksmbdpwd.db`) is leaked, passwords are trivially recoverable via rainbow tables or GPU-based cracking.

**Impact:** Password database compromise leads to immediate credential recovery. The base64-encoded MD4 hashes provide no meaningful defense against offline attacks.

**Recommendation:**
- Ensure the password database file has restrictive permissions (0600, root-owned)
- Document the inherent weakness in operational security guidance
- Consider supporting NTLMv2-only mode to discourage NTLMv1 which is even weaker
- Long-term: investigate Kerberos-only authentication to avoid NTLM entirely

---

### P1-03: `abort()` Calls in Daemon Can Cause Denial of Service

**Files:**
- `/home/ezechiel203/ksmbd/ksmbd-tools/mountd/rpc_samr.c`, line 1044
- `/home/ezechiel203/ksmbd/ksmbd-tools/mountd/rpc_lsarpc.c`, line 779
- `/home/ezechiel203/ksmbd/ksmbd-tools/mountd/ipc.c`, lines 591-622
- `/home/ezechiel203/ksmbd/ksmbd-tools/tools/management/spnego.c`, line 64
**Category:** Denial of Service / Error Handling

Multiple `abort()` calls exist in the daemon code paths. While these are generally in initialization code (`gethostname()` failures, netlink socket setup), the ones in `rpc_samr.c` and `rpc_lsarpc.c` are triggered by `gethostname()` failures during RPC initialization, which could potentially be triggered if the hostname is changed while the daemon is running and the init function is re-invoked.

The `ipc.c` abort calls are in netlink initialization and are less concerning (daemon cannot function without netlink), but `abort()` in a root daemon is still problematic as it produces a core dump that may contain sensitive credential material.

**Impact:** Denial of service via daemon crash. Core dump may expose password hashes or session keys in memory.

**Recommendation:**
- Replace `abort()` calls in RPC init functions with graceful error returns
- For `ipc.c`, consider using `_Exit(1)` instead of `abort()` to avoid core dumps
- Ensure core dump size limits are set to 0 in production deployments

---

## Medium Findings (P2)

### P2-01: Predictable SAMR Handle Generation

**File:** `/home/ezechiel203/ksmbd/ksmbd-tools/mountd/rpc_samr.c`, lines 80-102
**Category:** RPC Vulnerabilities / Weak Randomness

The `samr_ch_alloc()` function generates handles by incrementing the pipe ID:

```c
static struct connect_handle *samr_ch_alloc(unsigned int id)
{
    ...
    id++;
    memcpy(ch->handle, &id, sizeof(unsigned int));
    ...
}
```

This produces sequential, predictable handle values (1, 2, 3, ...) with the remaining 16 bytes of the 20-byte handle being zero. An attacker who can interact with the SAMR pipe can predict future handle values and potentially access handles created by other sessions.

**Impact:** Handle prediction could allow unauthorized access to SAMR operations (user enumeration, domain information) across sessions.

**Recommendation:** Use cryptographically random handle values:
```c
#include <sys/random.h>
getrandom(ch->handle, HANDLE_SIZE, 0);
```

---

### P2-02: SAMR Handle Lifetime Management Issues

**File:** `/home/ezechiel203/ksmbd/ksmbd-tools/mountd/rpc_samr.c`
**Category:** RPC Vulnerabilities / Resource Management

The SAMR connect handle system has several issues:

1. **No per-session handle scoping:** Handles are stored in a global hash table without any session affinity. Any RPC pipe can look up any handle.

2. **No handle limit:** There is no cap on the number of handles that can be allocated. An attacker could exhaust memory by repeatedly calling `samr_connect5` without closing handles.

3. **User pointer stored without reference management:** In `samr_lookup_names_return`, the user pointer is stored in `ch->user` without checking if a previous user was already stored there (potential reference leak).

**Impact:** Resource exhaustion, information disclosure across sessions.

**Recommendation:**
- Add per-session handle tracking
- Implement a maximum handle count
- Properly manage user references in connect handles

---

### P2-03: RID-to-UID Direct Mapping in LSARPC

**File:** `/home/ezechiel203/ksmbd/ksmbd-tools/mountd/rpc_lsarpc.c`, line 334
**Category:** Privilege Issues / Authorization Bypass

The `lsarpc_lookup_sid2_invoke()` function uses `getpwuid_r()` with the SID's RID (Relative Identifier) directly as a Unix UID:

```c
rid = ni->sid.sub_auth[ni->sid.num_subauth];
if (getpwuid_r(rid, &pwd_buf, pwd_str_buf,
               sizeof(pwd_str_buf), &passwd))
    passwd = NULL;
```

This creates a direct mapping between SMB RIDs and Unix UIDs. An attacker who can craft SID lookup requests can enumerate valid Unix users on the system by probing different RID values and observing whether lookup succeeds.

**Impact:** Unix user enumeration via crafted SID lookup requests.

**Recommendation:** Implement a proper RID-to-user mapping table rather than direct UID mapping.

---

### P2-04: Subauth Parser Integer Overflow

**File:** `/home/ezechiel203/ksmbd/ksmbd-tools/tools/config_parser.c`
**Category:** Config Parser Bugs / Integer Overflow

The `add_subauth()` function parses subauthority values from the configuration file using manual digit-to-integer conversion without overflow checking:

```c
global_conf.gen_subauth[i] *= 10;
global_conf.gen_subauth[i] += *entry - '0';
```

Since `gen_subauth` is `unsigned int [3]` (32-bit), a maliciously crafted subauth file with very long digit sequences could cause integer overflow, resulting in incorrect Security ID generation.

**Impact:** If an attacker can control the subauth configuration file, they could cause incorrect SID generation, potentially leading to privilege confusion.

**Recommendation:** Add overflow checking:
```c
if (global_conf.gen_subauth[i] > (UINT_MAX - (*entry - '0')) / 10)
    return;  // overflow
```

---

### P2-05: `control_debug()` Passes Unvalidated User Input to Sysfs

**File:** `/home/ezechiel203/ksmbd/ksmbd-tools/control/control.c`, lines 276-320
**Category:** Command Injection / Input Validation

The `control_debug()` function writes user-supplied component name directly to the kernel sysfs attribute:

```c
int control_debug(char *comp)
{
    ...
    if (write(fd, comp, strlen(comp)) < 0) {
```

While the kernel sysfs handler should validate the input, passing arbitrary user strings to a kernel interface without userspace validation is a defense-in-depth gap. The `comp` parameter comes directly from `optarg` without any validation.

**Impact:** Low direct impact since the kernel should validate, but violates defense-in-depth principle.

**Recommendation:** Validate `comp` against the known list of components ("all", "smb", "auth", "vfs", "oplock", "ipc", "conn", "rdma") before writing to sysfs.

---

### P2-06: `strcpy` Use in Kerberos Authentication

**File:** `/home/ezechiel203/ksmbd/ksmbd-tools/tools/management/spnego_krb5.c`, line 291
**Category:** Memory Safety

```c
strcpy(auth_out->user_name, client_name);
```

While the buffer is allocated with the correct size (`strlen(client_name) + 1`), the use of `strcpy` is a fragile pattern. If the allocation logic changes or if `client_name` is modified between sizing and copying, a buffer overflow could occur.

**Impact:** Low probability of exploitation given current code, but fragile to future changes.

**Recommendation:** Replace with `memcpy` using the known length, or use `g_strdup()`.

---

### P2-07: FIFO Race Condition in `control_list()`

**File:** `/home/ezechiel203/ksmbd/ksmbd-tools/control/control.c`, lines 141-235
**Category:** Privilege Issues / Race Condition

The `control_list()` function creates a FIFO at a predictable path (`/run/ksmbd.fifo.<pid>`), then opens it. There is a TOCTOU race between `mkfifo()` and `open()` -- a local attacker could create a symlink at the FIFO path between these calls, potentially redirecting output.

```c
g_autofree char *fifo_path =
    g_strdup_printf("%s.%d", PATH_FIFO, getpid());
if (mkfifo(fifo_path, S_IRUSR | S_IWUSR) < 0) { ... }
fd = open(fifo_path, O_RDONLY | O_NONBLOCK);
```

**Impact:** Low -- requires local access and precise timing. The FIFO is created with restrictive permissions (0600).

**Recommendation:** Use `O_NOFOLLOW` when opening the FIFO, or use a temporary directory with restricted permissions.

---

## Low/Informational Findings (P3)

### P3-01: `try_realloc_payload()` Linear Growth Pattern

**File:** `/home/ezechiel203/ksmbd/ksmbd-tools/mountd/rpc.c`
**Category:** Performance / Resource Management

The `try_realloc_payload()` function grows the DCE/RPC payload buffer by a fixed 4096 bytes per call. For large RPC responses (up to `KSMBD_MAX_RPC_PAYLOAD_SZ` = 256KB), this results in many reallocations and copies.

**Impact:** Performance degradation for large RPC responses. Not a security issue per se, but excessive allocations could contribute to timing side channels.

**Recommendation:** Consider exponential growth (doubling) up to the maximum size.

---

### P3-02: `getgrouplist()` Retry Loop Lacks Bound

**File:** `/home/ezechiel203/ksmbd/ksmbd-tools/tools/management/user.c`
**Category:** Memory Safety / Denial of Service

The `getgrouplist()` call is retried in a loop when it returns -1 (buffer too small), reallocating with the returned `ngroups` each time. If `getgrouplist()` consistently returns -1 with increasing values (e.g., due to concurrent group database modifications), this could loop indefinitely.

**Impact:** Very low probability. Would require ongoing concurrent modification of the group database during user login processing.

**Recommendation:** Add a maximum iteration count (e.g., 10 retries).

---

### P3-03: Lock File PID Parsing Without Overflow Check

**File:** `/home/ezechiel203/ksmbd/ksmbd-tools/tools/config_parser.c`
**Category:** Config Parser Bugs

The `is_a_lock()` function manually parses PID values from the lock file without checking for integer overflow. While PIDs are typically bounded by the kernel's PID space (usually 32768 or 4194304), a corrupted lock file with an extremely long digit sequence could cause overflow.

**Impact:** Minimal -- would result in incorrect PID, causing the lock validation to fail (safe failure mode).

**Recommendation:** Use `strtol()` with range checking instead of manual parsing.

---

### P3-04: `strtok_r` Modifies Input String in LSARPC

**File:** `/home/ezechiel203/ksmbd/ksmbd-tools/mountd/rpc_lsarpc.c`
**Category:** Memory Safety

The `lsarpc_lookup_names3_invoke()` function uses `strtok_r()` to parse `DOMAIN\user` format strings. This modifies the input string in place, which could cause issues if the string is referenced again later.

**Impact:** Low -- the modified string is an NDR-read string that is not reused after tokenization.

**Recommendation:** Work on a copy of the string to avoid modifying NDR-owned data.

---

### P3-05: Password Visible in Process Arguments Briefly

**File:** `/home/ezechiel203/ksmbd/ksmbd-tools/adduser/adduser.c`, lines 91-94
**Category:** Password Handling

When a password is passed via `-p` on the command line, it is visible in `/proc/<pid>/cmdline` until `explicit_bzero(optarg, strlen(optarg))` is called. There is a brief window where the password is visible.

```c
case 'p':
    g_free(password);
    password = g_strdup(optarg);
    if (optarg)
        explicit_bzero(optarg, strlen(optarg));
    break;
```

**Impact:** Low -- the window is very brief. However, command-line passwords are a well-known anti-pattern.

**Recommendation:** The code already mitigates this by zeroing argv. Consider adding a warning in the help text that `-p` is less secure than interactive prompting. This is already best practice -- no code change needed, just documentation.

---

### P3-06: NDR Bind Request Allocations Based on Untrusted Counts

**File:** `/home/ezechiel203/ksmbd/ksmbd-tools/mountd/rpc.c`
**Category:** Memory Safety / Resource Management

The `dcerpc_parse_bind_req()` function allocates arrays based on `num_contexts` (u8, max 255) and `num_syntaxes` (u8, max 255) from untrusted NDR input. While bounded by the u8 type to 255 entries maximum, this is still allocation under attacker control.

**Impact:** Low -- maximum allocation is 255 * sizeof(struct), which is bounded and reasonable.

**Recommendation:** Consider adding explicit bounds checks for documentation clarity:
```c
if (dce->bi_req.num_contexts > MAX_BIND_CONTEXTS)
    return -EINVAL;
```

---

### P3-07: `sprintf` in `pr_hex_dump` Without Bounds Check

**File:** `/home/ezechiel203/ksmbd/ksmbd-tools/tools/tools.c`, lines 233-237
**Category:** Memory Safety

```c
xi += sprintf(xline + xi, "%02X ", 0xff & c);
si += sprintf(sline + si, "%c", c);
```

The `pr_hex_dump` function uses `sprintf` to format into fixed-size buffers. While the loop structure ensures the indices stay within bounds (16 bytes per line), `sprintf` is inherently unsafe.

**Impact:** Minimal -- the loop structure prevents overflow in practice.

**Recommendation:** Use `snprintf` for defense-in-depth.

---

### P3-08: Terminal Escape Sequence Injection

**File:** `/home/ezechiel203/ksmbd/ksmbd-tools/addshare/share_admin.c`
**File:** `/home/ezechiel203/ksmbd/ksmbd-tools/adduser/user_admin.c`
**Category:** Input Validation

The interactive prompting code uses ANSI escape sequences for cursor control. While the input is validated through `cp_printable()`, the output of share names and user names passed to `printf` with `%s` could contain escape sequences if an attacker can control the database contents.

**Impact:** Very low -- requires the attacker to already have write access to configuration files.

**Recommendation:** Sanitize display strings when printing to terminals.

---

## Positive Observations

### Credential Hygiene (Excellent)
- `explicit_bzero()` is consistently used to clear password material before freeing memory throughout the codebase: `user_admin.c` (lines 108, 138, 152, 261, 296, 377), `adduser.c` (line 170), `ksmbdctl.c`, and `spnego_krb5.c`.
- Password argv is zeroed immediately after copying (`adduser.c` line 94, `ksmbdctl.c`).
- The `md4_final()` function zeros the context structure after producing the hash.

### IPC Input Validation (Very Good)
- All IPC string fields are validated for NUL-termination before use (`worker.c`, `VALID_IPC_MSG` macro, `ipc_string_terminated()`).
- Message size validation: `ipc_msg_alloc()` checks `sz > SIZE_MAX - sizeof(struct ksmbd_ipc_msg) - 1`.
- SPNEGO blob length validated against message size.
- RPC payload size validated against message size.
- NLA policy with `minlen` enforcement for all netlink event types.

### NDR Parser Bounds Checking (Good)
- All `ndr_read_*` functions check `dce->offset + sizeof(type) > dce->payload_sz` before reading.
- `ndr_read_vstring()` validates actual_len against raw_len and checks remaining buffer space.
- `try_realloc_payload()` has overflow check: `data_sz > SIZE_MAX - dce->offset`.

### Process Isolation (Good)
- The daemon uses a fork-based worker model (`mountd.c`): the manager process supervises and restarts the worker.
- Signal handling is well-structured with proper signal blocking during critical sections.
- The worker process handles IPC events, and crashes result in automatic restart by the manager.

### ACL and SID Handling (Good)
- `SID_MAX_SUB_AUTHORITIES` (15) is enforced in `smb_read_sid()`, `smb_write_sid()`, and `smb_set_ace()`.
- `smb_sid_to_string()` properly checks `snprintf` return values.
- `num_sid` bounded to 256 in `lsarpc_lookup_sid2_invoke()`.

### Share Configuration (Good)
- `shm_share_config_payload_size()` validates paths and checks for INT_MAX overflow.
- `shm_handle_share_config_request()` validates remaining buffer space before writes.
- CIDR matching for hosts allow/deny uses `inet_pton()` properly with both AF_INET and AF_INET6.
- Share name validation enforces length limits and character restrictions.

### Thread Safety (Good)
- GRWLock used for pipes table, connect handle table, user/share maps.
- `ksmbd_health_status` declared as `volatile sig_atomic_t` for signal-safe access.
- Atomic operations used for `sessions_cap`.

### Configuration Parsing (Good)
- `cp_memparse()` has proper overflow checking for memory size suffixes.
- Lock file validation checks PID existence AND verifies the process name matches.
- UTF-8 validation on user passwords and share names.
- `cp_printable()` filters non-printable characters from configuration values.

---

## Test Coverage Assessment

### Existing Tests

The test suite contains 4 test files with a total of approximately 40 test cases:

| Test File | Focus | Cases | Coverage |
|-----------|-------|-------|----------|
| `test_config_parser.c` | Config parsing: booleans, memparse, longs, defaults, flags, protocol versions | ~30 | Good coverage of global config parsing |
| `test_host_acl.c` | CIDR/hostname matching: IPv4, IPv6, exact match, invalid CIDR | ~11 | Good coverage of match_host_cidr() |
| `test_ipc_request_validation.c` | IPC input validation: unterminated strings in login, logout, tree connect | 4 | Good regression tests for NUL-termination checks |
| `test_share_config_payload.c` | Share config serialization: sizing, veto lists, pipe shares, overflow | 8 | Good coverage of payload sizing/serialization |

### Critical Gaps

1. **DCE/RPC Subsystem (No Tests)**
   - No tests for NDR read/write functions
   - No tests for DCE/RPC bind parsing
   - No tests for the RPC pipe lifecycle (open/read/write/close)
   - No fuzz testing of NDR deserialization

2. **SAMR/LSARPC/SRVSVC/WKSSVC RPC Services (No Tests)**
   - No tests for any RPC service invoke/return functions
   - No tests for handle allocation/lookup/free
   - No tests for malformed RPC requests

3. **SPNEGO/Kerberos Authentication (No Tests)**
   - No tests for ASN.1 parsing
   - No tests for SPNEGO token processing
   - No tests for KRB5 authentication flow
   - The ASN.1 tag overflow (P1-01) is in untested code

4. **Administrative Tools (No Tests)**
   - No tests for `ksmbd.adduser` password processing
   - No tests for `ksmbd.addshare` option handling
   - No tests for `ksmbd.control` operations

5. **User Management (No Tests)**
   - No tests for user lookup, add, update, delete
   - No tests for guest account handling
   - No tests for supplementary group resolution

6. **Netlink Communication (No Tests)**
   - No tests for IPC message construction/parsing
   - No tests for netlink error handling

### Recommendations for Test Improvement

1. **Priority 1: NDR Parser Fuzzing** -- The NDR read functions process untrusted data from SMB clients via RPC. Create fuzz tests using libFuzzer or AFL that exercise `ndr_read_vstring()`, `ndr_read_int*()`, and `dcerpc_parse_bind_req()` with malformed inputs.

2. **Priority 2: ASN.1 Parser Tests** -- Create tests for `asn1_tag_decode()`, `asn1_length_decode()`, `asn1_oid_decode()` with edge cases including: zero-length tags, maximum-length tags, truncated sequences, and the overflow case from P1-01.

3. **Priority 3: RPC Service Tests** -- Create integration tests that exercise each RPC service with valid and invalid requests, including handle lifecycle tests and resource exhaustion scenarios.

4. **Priority 4: Password Processing Tests** -- Test the `process_password()` pipeline with: empty passwords, maximum-length passwords, non-UTF-8 input, and boundary conditions.

---

## Summary of Findings by Severity

| Severity | Count | Key Issues |
|----------|-------|------------|
| P0 (Critical) | 0 | -- |
| P1 (High) | 3 | ASN.1 tag overflow, MD4 password hashing, abort() in daemon |
| P2 (Medium) | 7 | Predictable SAMR handles, handle management issues, RID-UID mapping, subauth overflow, sysfs input validation, strcpy in KRB5, FIFO race |
| P3 (Low/Info) | 8 | Linear realloc growth, getgrouplist loop, lock PID parsing, strtok_r string modification, argv password visibility, NDR bind allocations, sprintf usage, escape injection |
| **Total** | **18** | |

---

## Files Reviewed

### Daemon Core
- `/home/ezechiel203/ksmbd/ksmbd-tools/mountd/mountd.c`
- `/home/ezechiel203/ksmbd/ksmbd-tools/mountd/ipc.c`
- `/home/ezechiel203/ksmbd/ksmbd-tools/mountd/worker.c`

### RPC Subsystem
- `/home/ezechiel203/ksmbd/ksmbd-tools/mountd/rpc.c`
- `/home/ezechiel203/ksmbd/ksmbd-tools/mountd/rpc_srvsvc.c`
- `/home/ezechiel203/ksmbd/ksmbd-tools/mountd/rpc_wkssvc.c`
- `/home/ezechiel203/ksmbd/ksmbd-tools/mountd/rpc_samr.c`
- `/home/ezechiel203/ksmbd/ksmbd-tools/mountd/rpc_lsarpc.c`
- `/home/ezechiel203/ksmbd/ksmbd-tools/mountd/smbacl.c`

### Tools and Utilities
- `/home/ezechiel203/ksmbd/ksmbd-tools/tools/main.c`
- `/home/ezechiel203/ksmbd/ksmbd-tools/tools/tools.c`
- `/home/ezechiel203/ksmbd/ksmbd-tools/tools/ksmbdctl.c`
- `/home/ezechiel203/ksmbd/ksmbd-tools/tools/config_parser.c`
- `/home/ezechiel203/ksmbd/ksmbd-tools/tools/asn1.c`

### Management Layer
- `/home/ezechiel203/ksmbd/ksmbd-tools/tools/management/user.c`
- `/home/ezechiel203/ksmbd/ksmbd-tools/tools/management/share.c`
- `/home/ezechiel203/ksmbd/ksmbd-tools/tools/management/session.c`
- `/home/ezechiel203/ksmbd/ksmbd-tools/tools/management/tree_conn.c`
- `/home/ezechiel203/ksmbd/ksmbd-tools/tools/management/spnego.c`
- `/home/ezechiel203/ksmbd/ksmbd-tools/tools/management/spnego_krb5.c`

### Add User Tool
- `/home/ezechiel203/ksmbd/ksmbd-tools/adduser/adduser.c`
- `/home/ezechiel203/ksmbd/ksmbd-tools/adduser/user_admin.c`
- `/home/ezechiel203/ksmbd/ksmbd-tools/adduser/user_admin.h`
- `/home/ezechiel203/ksmbd/ksmbd-tools/adduser/md4_hash.c`
- `/home/ezechiel203/ksmbd/ksmbd-tools/adduser/md4_hash.h`

### Add Share Tool
- `/home/ezechiel203/ksmbd/ksmbd-tools/addshare/addshare.c`
- `/home/ezechiel203/ksmbd/ksmbd-tools/addshare/share_admin.c`
- `/home/ezechiel203/ksmbd/ksmbd-tools/addshare/share_admin.h`

### Control Tool
- `/home/ezechiel203/ksmbd/ksmbd-tools/control/control.c`
- `/home/ezechiel203/ksmbd/ksmbd-tools/control/control.h`

### Include Headers
- `/home/ezechiel203/ksmbd/ksmbd-tools/include/tools.h`
- `/home/ezechiel203/ksmbd/ksmbd-tools/include/rpc.h`
- `/home/ezechiel203/ksmbd/ksmbd-tools/include/ipc.h`
- `/home/ezechiel203/ksmbd/ksmbd-tools/include/config_parser.h`
- `/home/ezechiel203/ksmbd/ksmbd-tools/include/worker.h`
- `/home/ezechiel203/ksmbd/ksmbd-tools/include/smbacl.h`
- `/home/ezechiel203/ksmbd/ksmbd-tools/include/management/share.h`
- `/home/ezechiel203/ksmbd/ksmbd-tools/include/management/user.h`
- `/home/ezechiel203/ksmbd/ksmbd-tools/include/management/spnego.h`
- `/home/ezechiel203/ksmbd/ksmbd-tools/include/linux/ksmbd_server.h`

### Test Files
- `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_config_parser.c`
- `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_host_acl.c`
- `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_ipc_request_validation.c`
- `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_share_config_payload.c`
