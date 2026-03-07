# KSMBD Protocol Compliance Review Report (2026-02-28)

## 1. Scope
Comprehensive review of `ksmbd` implementation against:
- **MS-SMB v20260114** (SMB1)
- **MS-SMB2 v20260114** (SMB2, SMB3.0, SMB3.0.2, SMB3.1.1)

## 2. Coverage Assessment

### 2.1 SMB1 (MS-SMB)
- **Status:** Partial Coverage (~12%)
- **Implementation:** `src/protocol/smb1/`
- **Missing Mandatory/Important Features:**
    - Most legacy `SMB_COM_*` commands (only ~30 out of 256 implemented).
    - Advanced printing support (`SMB_COM_OPEN_PRINT_FILE`, etc.).
    - Messaging support (`SMB_COM_SEND_MESSAGE`, etc.).
    - Old-style search and directory management.
- **Justification:** SMB1 is deprecated and maintained only for legacy compatibility. 100% coverage is not a goal for modern `ksmbd`.

### 2.2 SMB2/3 (MS-SMB2)
- **Status:** High Coverage (~95%)
- **Implementation:** `src/protocol/smb2/`
- **Missing Features (2026 Spec):**
    - `SMB2_SERVER_TO_CLIENT_NOTIFICATION` (Command 0x0013): Not implemented.
    - `SMB2_GLOBAL_CAP_NOTIFICATIONS` (Capability 0x00000080): Not supported.
    - `SMB2_NOTIFY_SESSION_CLOSED` structure: Missing.
    - Full support for `TREE_CONNECT_Request_Extension`.
- **Observations:** `ksmbd` covers almost all mandatory SMB3.1.1 features including signing, encryption, multi-channel, and pre-authentication integrity.

## 3. Fit & Compliance (Behavioral)

The implementation was checked against the "MUST" clauses in both specifications.

### 3.1 Recent Fixes (Verified)
- **Second NEGOTIATE:** Now correctly disconnects the connection instead of suppressing response.
- **Duplicate Contexts:** Now correctly returns `STATUS_INVALID_PARAMETER`.
- **Encryption Enforcement:** Now correctly disconnects unencrypted requests on encrypted sessions.
- **ChannelSequence Tracking:** Implemented on `ksmbd_file` and validated on state-modifying requests.
- **NameLength Validation:** Now checks for multiple of 2 (UTF-16LE).

### 3.2 Remaining Deviations
- **IOCTL Flags:** The spec requires `SMB2_0_IOCTL_IS_FSCTL (0x00000001)`. While `ksmbd` now rejects other values, it may still have edge cases with `0x00000000` from older clients.
- **TREE_CONNECT Extensions:** The `SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT` flag is recognized but the extension data is ignored.
- **FSCTL Support:** Several "SHOULD" level FSCTLs (Compression, SID lookup) are missing, though spec-compliant (returns `STATUS_NOT_SUPPORTED`).

## 4. Conclusion
`ksmbd` is **highly compliant** with SMB2/3 but **not 100% compliant** with the latest 2026 specification due to the missing one-way notification mechanism. SMB1 support is intentionally limited to a functional subset.

---

# Remediation Plan (2026-02-28)

| ID | Description | Severity | Action |
|----|-------------|----------|--------|
| R-01 | Implement `SMB2_SERVER_TO_CLIENT_NOTIFICATION` | MEDIUM | Add command 0x0013 and notification infrastructure for session closure. |
| R-02 | Support `SMB2_GLOBAL_CAP_NOTIFICATIONS` | LOW | Negotiate notifications capability in NEGOTIATE. |
| R-03 | Parse `TREE_CONNECT_Request_Extension` | LOW | Extract `RedirectorFlags` if present. |
| R-04 | Enhance FSCTL coverage | LOW | Implement `FSCTL_QUERY_ALLOCATED_RANGES` for sparse file optimization. |
| R-05 | SMB1 Deprecation Path | INFO | Continue minimizing SMB1 surface area to reduce security risks. |
