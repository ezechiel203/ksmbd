# KSMBD Security Review - Quick Reference

## TL;DR

| Aspect | Rating | Notes |
|--------|--------|-------|
| Overall Security | B+ | Good practices, minor issues to address |
| Code Quality | A- | Clean, well-structured |
| Input Validation | B+ | Comprehensive but some edge cases |
| Memory Safety | A- | Uses modern kernel APIs |
| Cryptography | A | Standard algorithms, correct implementation |
| Ready for Production | Yes | With medium issues addressed |

## Immediate Actions Required

### 🔴 Fix These Before Production

1. **auth.c:595** - Add individual offset bounds check before addition
2. **share_config.c:190** - Fix path traversal check to catch `../` at start
3. **transport_ipc.c:115** - Add maximum length for RPC/SPNEGO events

### 🟡 Fix Soon (Next Release)

4. **vfs.c:597** - Add iteration limit for xattr processing
5. **transport_tcp.c:411** - Add absolute timeout for socket reads
6. **smb2_create.c:907** - Review stream parsing order

## Critical Code Paths

```
Network Input
    │
    ▼
┌─────────────────────────────────────┐
│  connection.c:490                   │  Connection handler loop
│  - Size validation                  │  ✅ PDU size checked
│  - Overflow protection              │  ✅ Uses check_add_overflow()
└─────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────┐
│  smb2_pdu_common.c                  │  Protocol dispatch
│  - Credit management                │  ✅ Overflow protected
│  - Chained message handling         │  ✅ Bounds checked
└─────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────┐
│  smb2_create.c:810                  │  File operations (CRITICAL)
│  - Path validation                  │  ✅ LOOKUP_BENEATH
│  - Post-open TOCTOU check           │  ✅ path_is_under()
│  - Stream handling                  │  ⚠️ Review order
└─────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────┐
│  vfs.c                              │  VFS operations
│  - Path lookup                      │  ✅ Safe APIs
│  - Xattr handling                   │  ⚠️ Unbounded iteration
└─────────────────────────────────────┘
```

## Security Controls Inventory

| Control | Implementation | Status |
|---------|---------------|--------|
| Path Traversal Prevention | `LOOKUP_BENEATH` + post-open verify | ✅ Strong |
| Integer Overflow Protection | `check_*_overflow()` macros | ✅ Comprehensive |
| Buffer Overflow Prevention | Length checks, `kvmalloc()` | ✅ Good |
| Timing Attack Prevention | `crypto_memneq()` | ✅ Used correctly |
| Memory Clearing | `memzero_explicit()` | ✅ Used for secrets |
| Race Condition Prevention | RCU, proper locking | ✅ Good |
| Session Management | `refcount_t`, state machine | ✅ Good |
| Authentication | NTLMv2, Kerberos, SMB signing | ✅ Correct |
| Encryption | AES-CCM, AES-GCM | ✅ Correct |

## Dangerous Functions Audit

| Function | Used | Count | Status |
|----------|------|-------|--------|
| `memcpy()` | Yes | ~50 | ✅ Lengths validated |
| `strcpy()` | No | 0 | ✅ Not used |
| `strncpy()` | Yes | ~5 | ⚠️ Review for null termination |
| `sprintf()` | No | 0 | ✅ Not used |
| `kmalloc()` | Yes | ~100 | ✅ Sizes checked |
| `vmalloc()` | Yes | ~10 | ✅ For large allocations |
| `copy_from_user()` | No | 0 | ✅ Not used (netlink IPC) |

## Testing Recommendations

### Run These Before Release

```bash
# 1. Static analysis with sparse
make C=1 CF="-D__CHECK_ENDIAN__" M=fs/ksmbd

# 2. Build with all warnings
cd /path/to/kernel
make W=1 M=fs/ksmbd 2>&1 | grep -i "ksmbd.*warning"

# 3. Memory sanitizer (KASAN)
# Enable CONFIG_KASAN in kernel config
# Run smbclient torture tests

# 4. Fuzzing
# Build with KSMBD_FUZZ=y
# Run against the fuzz harnesses in test/fuzz/

# 5. Protocol compliance
# Run smbtorture against the server
smbtorture //localhost/share smb2.create
smbtorture //localhost/share smb2.session

# 6. Security-specific tests
# - Path traversal attempts
# - Long paths (>4096 chars)
# - Invalid Unicode sequences
# - Malformed security descriptors
# - Oversized create contexts
```

## Monitoring Checklist

### Enable These Log Points

```bash
# Authentication events
echo 'module ksmbd +p' > /sys/kernel/debug/dynamic_debug/control
echo 'func ksmbd_decode_ntlmssp_auth_blob +p' >> /sys/kernel/debug/dynamic_debug/control

# File operations
echo 'func smb2_open +p' >> /sys/kernel/debug/dynamic_debug/control

# Errors
dmesg -n alert
```

### Watch For These Patterns

```bash
# Real-time security monitoring
dmesg -w | grep -E "(
    escapes share root|
    client GUID mismatch|
    Total credits overflow|
    PDU length.*exceed|
    authentication failed|
    Invalid.*blob|
    bad smb2 signature
)"
```

## Configuration Security

### Secure ksmbd.conf Template

```ini[global]
; Minimum protocol - disable SMB1
server min protocol = SMB2_10
server max protocol = SMB3_11

; Require encryption (if all clients support it)
server smb encrypt = required

; Require signing
server signing = mandatory

; Connection limits
max connections = 1000
max ip connections = 100

; Timeouts
deadtime = 15

[share]
; Path must be absolute without .. components
path = /srv/samba/share
; NOT: path = /srv/share/../data  <- REJECTED

; Restrict access
valid users = @users
read only = no

; Veto dangerous files
veto files = /*.exe/*.dll/*.bat/
```

## Incident Response

### If You Suspect a Compromise

1. **Stop immediately:**
   ```bash
   sudo ksmbd.control -s
   sudo rmmod ksmbd
   ```

2. **Preserve evidence:**
   ```bash
   sudo dmesg > /var/log/ksmbd-incident-$(date +%s).log
   sudo cat /sys/class/ksmbd-control/debug > /var/log/ksmbd-debug.log
   ```

3. **Check for indicators:**
   ```bash
   # Unexpected kernel modules
   lsmod
   
   # Unusual network connections
   ss -tap | grep 445
   
   # Recent files accessed
   find /srv/samba -type f -mtime -1
   ```

## References

- Full Review: `KSECURITY_REVIEW.md`
- SMB2 Spec: [MS-SMB2](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/)
- Kernel Security: [KernelHardening](https://www.kernel.org/doc/html/latest/security/)

---

*Quick reference generated: 2026-02-24*
