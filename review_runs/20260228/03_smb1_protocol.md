# SMB1 Protocol Handling - Security Code Review

**Reviewer:** Claude Opus 4.6
**Date:** 2026-02-28
**Scope:** SMB1 protocol implementation in ksmbd kernel module
**Files Reviewed:**
- `src/protocol/smb1/smb1pdu.c` (9430 lines)
- `src/protocol/smb1/smb1misc.c` (326 lines)
- `src/protocol/smb1/smb1ops.c` (98 lines)
- `src/include/protocol/smb1pdu.h` (1652 lines)
- `src/include/protocol/smberr.h` (236 lines)

---

## Executive Summary

The SMB1 protocol implementation in ksmbd has received substantial security hardening relative to typical legacy SMB1 codebases. Buffer validation helpers (`smb1_validate_trans2_buffer`, `smb1_validate_data_offset`) using `check_add_overflow()` have been added for TRANS2 commands. AndX chaining includes forward-progress enforcement and depth limiting. Lock array bounds are properly validated. The echo handler caps iteration counts and checks response buffer capacity. The known `__fortify_memcpy` WARN_ON issue at lines 1391 and 1473 has been mitigated with `noinline` barrier helpers (`smb1_copy_area`, `smb1_zero_area`).

However, several security concerns remain. The most significant are: (1) signing verification is skipped for session setup and tree connect commands, weakening man-in-the-middle protection during the most security-critical phase of connection establishment; (2) the non-extended-security authentication path (`build_sess_rsp_noextsec`) accepts legacy NTLM/NTLMv2 over a potentially unsigned channel; (3) the `smb_write` (32-bit variant) handler does not validate that the `Data` pointer falls within the request buffer; (4) several TRANS2 sub-command handlers could benefit from additional input bounds checking; and (5) the `smb1_check_message` function tolerates up to 512 bytes of excess data, which while documented, could still mask malformed packets.

Overall the code is in a reasonably good security posture for a legacy protocol that is inherently less secure than SMB2/3. The critical recommendations below focus on tightening the remaining gaps.

**Finding Summary:**
- Critical (P0): 1
- High (P1): 5
- Medium (P2): 6
- Low/Informational (P3): 6

---

## Critical Findings (P0)

### P0-1: SMB1 Signing Bypass for Session Setup and Tree Connect

**File:** `src/protocol/smb1/smb1pdu.c:9339-9355`
**Severity:** Critical
**CWE:** CWE-345 (Insufficient Verification of Data Authenticity)

**Description:**
The `smb1_is_sign_req()` function explicitly skips signature verification for `SMB_COM_SESSION_SETUP_ANDX` and `SMB_COM_TREE_CONNECT_ANDX` commands. The code comment states this is for "legacy compatibility (Windows XP)" but these are the most security-sensitive commands in the SMB1 protocol -- they carry authentication credentials and establish share access.

```c
if ((rcv_hdr1->Flags2 & SMBFLG2_SECURITY_SIGNATURE) &&
    command != SMB_COM_SESSION_SETUP_ANDX &&
    command != SMB_COM_TREE_CONNECT_ANDX)
        return true;
return false;
```

An active man-in-the-middle attacker can modify session setup requests/responses (injecting a downgrade to weaker authentication or altering NTLMSSP challenge messages) and tree connect requests (redirecting to a different share) without detection, even when signing is negotiated and enabled for the connection. The signing verification for session setup typically uses a well-known key (before the session key is established), so it can be verified; for tree connect the session key is already available.

**Impact:** A network-level attacker can tamper with authentication and share connection commands without detection, enabling credential theft, session hijacking, or unauthorized share access on connections that have negotiated signing.

**Fix:**
```c
/*
 * Option 1: Verify tree connect signing (session key is available).
 * Only skip session setup signing when the session key is not yet
 * established (first round of session setup).
 */
bool smb1_is_sign_req(struct ksmbd_work *work, unsigned int command)
{
    struct smb_hdr *rcv_hdr1 = (struct smb_hdr *)work->request_buf;

    if (!(rcv_hdr1->Flags2 & SMBFLG2_SECURITY_SIGNATURE))
        return false;

    /* Only skip the first session setup (session key not yet available) */
    if (command == SMB_COM_SESSION_SETUP_ANDX && !work->sess)
        return false;

    return true;
}
```

Alternatively, make the skip behavior configurable via a server configuration parameter so administrators can enforce strict signing for environments that do not need Windows XP compatibility.

---

## High Findings (P1)

### P1-1: Legacy Non-Extended-Security Authentication Allows Weak NTLM

**File:** `src/protocol/smb1/smb1pdu.c:1172-1314` (`build_sess_rsp_noextsec`)
**Severity:** High
**CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)

**Description:**
The `build_sess_rsp_noextsec()` function handles authentication for clients that do not use extended security (no SPNEGO). It accepts plain NTLMv1 authentication when `CaseSensitivePasswordLength == CIFS_AUTH_RESP_SIZE` (24 bytes), calling `ksmbd_auth_ntlm()`. NTLMv1 is cryptographically weak and susceptible to pass-the-hash attacks and rainbow table recovery. There is no configuration option to disable this legacy path or require NTLMv2 minimum.

```c
if (le16_to_cpu(req->CaseSensitivePasswordLength) ==
        CIFS_AUTH_RESP_SIZE) {
    err = ksmbd_auth_ntlm(sess, req->CaseInsensitivePassword +
        le16_to_cpu(req->CaseInsensitivePasswordLength),
        conn->ntlmssp.cryptkey);
```

**Impact:** An attacker who can perform offline brute force or rainbow table attack against captured NTLMv1 responses can recover user passwords. On a network where NTLMv2 is expected, a downgrade attacker could force the client to use NTLMv1.

**Fix:** Add a server configuration option (e.g., `min_auth_level`) that defaults to requiring NTLMv2 or extended security. When set, `build_sess_rsp_noextsec()` should reject NTLMv1 authentication and return `STATUS_ACCESS_DENIED`. Consider logging a warning when this legacy path is used.

---

### P1-2: smb_write (32-bit) Missing Data Buffer Bounds Validation

**File:** `src/protocol/smb1/smb1pdu.c:3477-3531` (`smb_write`)
**Severity:** High
**CWE:** CWE-125 (Out-of-bounds Read)

**Description:**
The `smb_write()` handler for `SMB_COM_WRITE` (the 32-bit write variant) sets `data_buf = req->Data` without validating that the data area actually falls within the request buffer bounds. The `count` (from `req->Length`) is used directly to write from `data_buf` to the VFS without checking that `offsetof(struct smb_com_write_req_32bit, Data) + count` does not exceed the RFC1002 length.

```c
pos = le32_to_cpu(req->Offset);
count = le16_to_cpu(req->Length);
data_buf = req->Data;
// No validation that data_buf + count is within request_buf bounds
err = ksmbd_vfs_write(work, fp, data_buf, count, &pos, 0, &nbytes);
```

This is in contrast to `smb_write_andx()` which does validate `DataOffset` and `count` against `get_rfc1002_len()`. A crafted SMB_COM_WRITE packet with a `Length` exceeding the actual packet size could cause reading beyond the request buffer into adjacent kernel memory and writing that data to a file.

**Impact:** An authenticated attacker could read kernel heap memory beyond the request buffer by crafting a packet with a large `Length` field and small actual payload, potentially extracting sensitive kernel data (information disclosure) that gets written to a file the attacker controls.

**Fix:**
```c
pos = le32_to_cpu(req->Offset);
count = le16_to_cpu(req->Length);
data_buf = req->Data;

/* Validate data area fits within request buffer */
{
    unsigned int req_buf_len = get_rfc1002_len(work->request_buf) + 4;
    unsigned int data_off = offsetof(typeof(*req), Data);

    if (data_off + count > req_buf_len) {
        pr_err("SMB_COM_WRITE data length %zu exceeds request buffer\n",
               count);
        rsp->hdr.Status.CifsError = STATUS_INVALID_PARAMETER;
        ksmbd_fd_put(work, fp);
        return -EINVAL;
    }
}
```

---

### P1-3: Echo Handler Does Not Validate req->Data Against Request Buffer

**File:** `src/protocol/smb1/smb1pdu.c:3755`
**Severity:** High
**CWE:** CWE-125 (Out-of-bounds Read)

**Description:**
The echo handler validates that `data_count` fits within the *response* buffer but does not validate that `data_count` bytes are actually available in the *request* buffer starting from `req->Data`. If `req->ByteCount` (which populates `data_count`) exceeds the actual request payload, the `memcpy(rsp->Data, req->Data, data_count)` will read beyond the request buffer.

```c
data_count = le16_to_cpu(req->ByteCount);

/* Only validates against response buffer, not request buffer */
if (data_count > work->response_sz - offsetof(struct smb_com_echo_rsp, Data)) {
    ...
}

memcpy(rsp->Data, req->Data, data_count);  // reads from request buffer
```

The pre-validation in `ksmbd_smb1_check_message()` checks that the byte count field value matches the packet length, so under normal conditions the byte count should be consistent with the packet. However, `ksmbd_smb1_check_message()` tolerates excess (len > clc_len by up to 512 bytes), and the byte count value itself comes from within the packet and is trusted after the structural check. If the structural check passes but the field is manipulated (or the message was only partially received), the read could go out of bounds.

**Impact:** Potential kernel heap information disclosure via reading beyond the request buffer into adjacent allocations, with the data returned to the client in the echo response.

**Fix:** Add a validation that `data_count` is within the request buffer:
```c
{
    unsigned int req_buf_len = get_rfc1002_len(work->request_buf) + 4;
    unsigned int data_off = offsetof(struct smb_com_echo_req, Data);

    if (data_off + data_count > req_buf_len) {
        pr_err("Echo data_count %u exceeds request buffer\n", data_count);
        rsp->hdr.Status.CifsError = STATUS_INVALID_PARAMETER;
        return -EINVAL;
    }
}
```

---

### P1-4: Sequence Number Not Cryptographically Verified in Signing

**File:** `src/protocol/smb1/smb1pdu.c:9363-9391` (`smb1_check_sign_req`)
**Severity:** High
**CWE:** CWE-354 (Improper Validation of Integrity Check Value)

**Description:**
In `smb1_check_sign_req()`, the sequence number is incremented by the server (`++work->sess->sequence_number`) and used for signature verification. However, the server blindly increments its own counter and does not cross-check that it matches the client's intended sequence number from the request. If sequence numbers go out of sync (e.g., due to dropped packets, retransmissions, or cancel commands), subsequent signature verification will fail for all commands, causing a denial of service. Additionally, the sequence number is a simple `unsigned int` that will wrap around after approximately 4 billion messages, though this is unlikely to be exploited in practice.

More importantly, the signature comparison uses `memcmp()` which is not constant-time. While exploiting timing side-channels over a network is extremely difficult, best practice for cryptographic comparison is to use `crypto_memneq()`.

```c
rcv_hdr1->Signature.Sequence.SequenceNumber =
    cpu_to_le32(++work->sess->sequence_number);
// ...
if (memcmp(signature, signature_req, CIFS_SMB1_SIGNATURE_SIZE)) {
```

**Impact:** (1) Sequence synchronization issues could cause legitimate clients to be locked out. (2) Theoretical timing side-channel for signature bypass (extremely low practical risk over network).

**Fix:** Use `crypto_memneq()` for constant-time comparison:
```c
if (crypto_memneq(signature, signature_req, CIFS_SMB1_SIGNATURE_SIZE)) {
    ksmbd_debug(SMB, "bad smb1 sign\n");
    return 0;
}
```
Also consider adding sequence number synchronization recovery logic and rate-limiting logging of signature failures to aid in debugging without flooding the kernel log.

---

### P1-5: NTLMv2 Authentication Response Length Not Fully Validated

**File:** `src/protocol/smb1/smb1pdu.c:1262-1268` (`build_sess_rsp_noextsec`)
**Severity:** High
**CWE:** CWE-119 (Improper Restriction of Operations within the Bounds of a Memory Buffer)

**Description:**
When the non-extended-security path handles NTLMv2 authentication, it computes the NTLMv2 response length by subtracting `CIFS_ENCPWD_SIZE` from `CaseSensitivePasswordLength`, but does not check that `CaseSensitivePasswordLength >= CIFS_ENCPWD_SIZE`. If the client sends a `CaseSensitivePasswordLength` less than `CIFS_ENCPWD_SIZE`, the subtraction produces a very large unsigned value (integer underflow), which could cause `ksmbd_auth_ntlmv2()` to read far beyond the request buffer.

```c
err = ksmbd_auth_ntlmv2(conn, sess,
    (struct ntlmv2_resp *) ((char *)
    req->CaseInsensitivePassword +
    le16_to_cpu(req->CaseInsensitivePasswordLength)),
    le16_to_cpu(req->CaseSensitivePasswordLength) -
        CIFS_ENCPWD_SIZE, ntdomain,
        conn->ntlmssp.cryptkey);
```

**Impact:** An unauthenticated attacker can trigger an out-of-bounds read in the kernel by sending a crafted session setup request with a small `CaseSensitivePasswordLength`. This could lead to a kernel crash or information disclosure.

**Fix:**
```c
u16 cs_pw_len = le16_to_cpu(req->CaseSensitivePasswordLength);
if (cs_pw_len < CIFS_ENCPWD_SIZE) {
    err = -EINVAL;
    goto out_err;
}

err = ksmbd_auth_ntlmv2(conn, sess,
    (struct ntlmv2_resp *) ((char *)
    req->CaseInsensitivePassword +
    le16_to_cpu(req->CaseInsensitivePasswordLength)),
    cs_pw_len - CIFS_ENCPWD_SIZE, ntdomain,
    conn->ntlmssp.cryptkey);
```

---

## Medium Findings (P2)

### P2-1: NTLMv2 Domain Name Offset Calculation Uses strlen(user_name) Without Bounds Check

**File:** `src/protocol/smb1/smb1pdu.c:1243-1251`
**Severity:** Medium
**CWE:** CWE-131 (Incorrect Calculation of Buffer Size)

**Description:**
In the NTLMv2 path within `build_sess_rsp_noextsec()`, the NT domain name offset is calculated using `strlen(user_name(sess->user))`. The user name was extracted from the request buffer earlier and its length is assumed to match the actual username string in the request. However, the offset calculation multiplies by 2 (for Unicode) and adds the password lengths. If the username string in the request is shorter than the one returned by `ksmbd_login_user()` (after normalization), the computed offset could overshoot the actual domain string location.

The code does have a bounds check:
```c
if (offsetof(typeof(*req), CaseInsensitivePassword) + offset + 1 >
    get_rfc1002_len(&req->hdr) + 4) {
    err = -EINVAL;
    goto out_err;
}
```

This mitigates a buffer overrun, but the domain name extraction could still read garbage data from an incorrect offset, potentially passing invalid data to `ksmbd_auth_ntlmv2()`.

**Impact:** Low risk of buffer overrun (bounds check present), but incorrect domain name could cause authentication to fail or succeed for wrong reasons.

**Fix:** Parse the domain name from the request by scanning the buffer sequentially after the username, rather than computing a fixed offset based on the looked-up username length. This ensures the domain string is extracted from the correct position regardless of username normalization.

---

### P2-2: smb_write_andx_pipe Does Not Validate Data Buffer Offset

**File:** `src/protocol/smb1/smb1pdu.c:3539-3567` (`smb_write_andx_pipe`)
**Severity:** Medium
**CWE:** CWE-125 (Out-of-bounds Read)

**Description:**
The pipe write handler `smb_write_andx_pipe()` passes `req->Data` directly to `ksmbd_rpc_write()` with a `count` derived from `DataLengthLow` (and optionally `DataLengthHigh`). Unlike `smb_write_andx()` which validates `DataOffset`, the pipe path does not verify that `req->Data + count` is within the request buffer.

```c
count = le16_to_cpu(req->DataLengthLow);
if (work->conn->vals->capabilities & CAP_LARGE_WRITE_X)
    count |= (le16_to_cpu(req->DataLengthHigh) << 16);

rpc_resp = ksmbd_rpc_write(work->sess, req->Fid, req->Data, count);
```

**Impact:** An authenticated attacker connected to an IPC$ share could potentially trigger an out-of-bounds read by sending a pipe write with a `DataLengthLow/High` larger than the actual packet, causing kernel memory to be written to the RPC pipe.

**Fix:** Validate that the data area fits within the request buffer before calling `ksmbd_rpc_write()`, similar to the validation in `smb_write_andx()`.

---

### P2-3: Message Validation Tolerates 512 Bytes of Excess Data

**File:** `src/protocol/smb1/smb1misc.c:295-311`
**Severity:** Medium
**CWE:** CWE-20 (Improper Input Validation)

**Description:**
`ksmbd_smb1_check_message()` allows packets that are up to 512 bytes longer than the calculated expected size to pass validation. While the code comments explain this as tolerance for "padding or client quirks," 512 bytes is a generous margin that could mask malformed packets containing extra trailing data.

```c
if (len - clc_len > 512) {
    pr_err("cli req excessively long, len %d not %d (excess %d). cmd:%x\n",
           len, clc_len, len - clc_len, command);
    return 1;
}
ksmbd_debug(SMB, "cli req too long, len %d not %d. cmd:%x\n",
    len, clc_len, command);
return 0;
```

Individual command handlers that parse variable-length fields from the request must not rely on the message-level validation alone, since up to 512 bytes of "extra" data is tolerated.

**Impact:** Excess data in packets could be misinterpreted by command handlers that scan for strings or structures past the expected end. The risk is mitigated by the fact that individual handlers generally use their own bounds checking, but any handler that relies solely on message-level validation could be affected.

**Fix:** Consider reducing the tolerance to a smaller value (e.g., 64 bytes) or making it configurable. At minimum, ensure that all command handlers perform their own bounds checking rather than relying on message-level validation.

---

### P2-4: SPNEGO Blob Size Not Validated Before Copy to Response Buffer

**File:** `src/protocol/smb1/smb1pdu.c:1391-1392, 1473-1474`
**Severity:** Medium
**CWE:** CWE-120 (Buffer Copy without Checking Size of Input)

**Description:**
When copying SPNEGO blobs to the response buffer in `build_sess_rsp_extsec()`, the code uses `smb1_copy_area()` (the `noinline` wrapper) to copy `spnego_blob_len` bytes to `rsp->SecurityBlob`. While the `noinline` attribute successfully suppresses the `__fortify_memcpy` warning (the known issue at lines 1391 and 1473), the fundamental concern remains: there is no explicit check that `spnego_blob_len` fits within the available response buffer space.

```c
smb1_copy_area((char *)rsp->SecurityBlob, spnego_blob,
              spnego_blob_len);
```

The response buffer is allocated as `MAX_CIFS_SMALL_BUFFER_SIZE` (typically 448 bytes) by `smb_allocate_rsp_buf()`. The SPNEGO blob is generated by `build_spnego_ntlmssp_neg_blob()` whose output size depends on the NTLMSSP challenge message size, which includes the server's NetBIOS name. Under normal conditions the blob should be well within the buffer, but there is no defensive check.

**Impact:** If the SPNEGO blob exceeds the response buffer size (e.g., due to an extremely long server NetBIOS name or a bug in blob construction), a heap buffer overflow in kernel space would occur, potentially leading to privilege escalation.

**Fix:**
```c
if (spnego_blob_len > work->response_sz -
    offsetof(struct smb_com_session_setup_resp, SecurityBlob)) {
    kfree(spnego_blob);
    kfree(neg_blob);
    err = -EINVAL;
    goto out_err;
}
smb1_copy_area((char *)rsp->SecurityBlob, spnego_blob,
              spnego_blob_len);
```

---

### P2-5: set_service_type Uses PATH_MAX Without Checking Response Buffer Capacity

**File:** `src/protocol/smb1/smb1pdu.c:563-591` (`set_service_type`)
**Severity:** Medium
**CWE:** CWE-120 (Buffer Copy without Checking Size of Input)

**Description:**
The `set_service_type()` function calls `smbConvertToUTF16()` with `PATH_MAX` as the maximum length for the native filesystem name string. The result is written into `rsp->Service` (which is a trailing `[1]` array in the response buffer) at an offset after the service type string. There is no check that the total length fits within the response buffer.

```c
uni_len = smbConvertToUTF16((__le16 *)(buf + length),
                NATIVE_FILE_SYSTEM, PATH_MAX,
                conn->local_nls, 0);
```

Since `NATIVE_FILE_SYSTEM` is the constant string "NTFS" (4 characters, 10 bytes in UTF-16 including null), the actual output is always small. However, the use of `PATH_MAX` as the size limit and the lack of response buffer bounds checking makes this code fragile if the constant is ever changed.

**Impact:** Currently low risk since the input is a constant. Would become exploitable if the `NATIVE_FILE_SYSTEM` string source were changed to a variable.

**Fix:** Replace `PATH_MAX` with a computed maximum based on the remaining response buffer capacity.

---

### P2-6: build_sess_rsp_noextsec Writes Native OS/LanMan Strings Without Buffer Check

**File:** `src/protocol/smb1/smb1pdu.c:1282-1301`
**Severity:** Medium
**CWE:** CWE-120 (Buffer Copy without Checking Size of Input)

**Description:**
In `build_sess_rsp_noextsec()`, the response builder writes three UTF-16 strings (NativeOS "Unix", NativeLanMan "ksmbd", PrimaryDomain "WORKGROUP") into the response buffer at `rsp->NativeOS + offset`. The `NativeOS` field is declared as `unsigned char NativeOS[1]` -- a trailing array marker. While the actual string content is short (constant strings totaling approximately 40 bytes in UTF-16), there is no explicit validation that `offset` stays within the response buffer bounds.

```c
len = smb_strtoUTF16(str, "Unix", 4, conn->local_nls);
len = UNICODE_LEN(len + 1);
memcpy(rsp->NativeOS + offset, str, len);
offset += len;
// ... similar for "ksmbd" and "WORKGROUP"
```

**Impact:** Currently low risk due to constant input strings, but the pattern is fragile and lacks defensive bounds checking.

**Fix:** Validate that `offsetof(typeof(*rsp), NativeOS) + offset + len` does not exceed `work->response_sz` before each `memcpy`.

---

## Low/Informational Findings (P3)

### P3-1: smb1_ops.c Uses kmemdup for Static Server Values

**File:** `src/protocol/smb1/smb1ops.c:87-90`
**Severity:** Informational

**Description:**
`init_smb1_server()` uses `kmemdup()` to create a per-connection copy of `smb1_server_values`. This is correct and necessary since the connection may modify protocol values during negotiation. However, the ops pointer (`conn->ops = &smb1_server_ops`) points to a shared static structure. If a bug in connection handling were to modify ops fields, it would affect all connections. This is consistent with the SMB2 implementation and is by design, but worth noting.

**Impact:** No direct security impact; defense-in-depth observation.

---

### P3-2: smb_cmd_to_str Returns Non-NULL for Array Gaps

**File:** `src/protocol/smb1/smb1pdu.c:75-81`
**Severity:** Informational

**Description:**
`smb_cmd_to_str()` returns `smb_cmd_str[cmd]` for any `cmd < ARRAY_SIZE(smb_cmd_str)`. Since the array is sparsely populated (indexed by command code, many entries are NULL), this can return NULL for unsupported commands between 0 and the array size. The caller in `smb_check_user_session()` passes the result to `ksmbd_debug()` which uses `%s` format. Passing NULL to `%s` is undefined behavior in standard C, though Linux's `printk` handles it by printing "(null)".

**Impact:** No security impact on Linux kernels (printk handles NULL), but technically undefined behavior per C standard.

**Fix:** Return "unknown_cmd" for NULL array entries:
```c
if (cmd < ARRAY_SIZE(smb_cmd_str) && smb_cmd_str[cmd])
    return smb_cmd_str[cmd];
return "unknown_cmd";
```

---

### P3-3: TODO Comments Indicate Incomplete Validation

**File:** `src/protocol/smb1/smb1misc.c:20-21, 35`
**Severity:** Informational

**Description:**
Two TODO comments in `smb1misc.c` indicate areas where validation is acknowledged as incomplete:
- Line 20-21: "TODO: properly check client authentication and tree authentication" in `check_smb1_hdr()`
- Line 35: "TODO: check for oplock break" -- oplock breaks from the server side are not validated.

These are pre-existing TODOs that should be tracked.

**Impact:** Incomplete validation as documented by the developers.

---

### P3-4: smb_com_lock_req Uses `char *Locks[1]` Instead of Flexible Array

**File:** `src/include/protocol/smb1pdu.h:463`
**Severity:** Informational

**Description:**
The `smb_com_lock_req` structure declares its trailing lock array as `char *Locks[1]`, which is an array of pointers, not an array of bytes or a flexible array member. On a 64-bit system, `sizeof(char *) == 8`, so `Locks[1]` occupies 8 bytes. The code in `smb_locking_andx()` casts `req->Locks` to either `locking_andx_range32` or `locking_andx_range64` pointers, which works correctly because the cast operates on the address. However, using `char *Locks[1]` instead of `char Locks[]` or `__u8 Locks[0]` is misleading and could cause incorrect `sizeof` calculations if used elsewhere.

**Impact:** No runtime impact since the lock validation code uses `offsetof(typeof(*req), Locks)` which correctly computes the offset. But the declaration is misleading.

**Fix:** Change to `__u8 Locks[]` (flexible array member) or `__u8 Locks[0]` for clarity.

---

### P3-5: check_smb1_hdr Uses Type Punning for Protocol Number Check

**File:** `src/protocol/smb1/smb1misc.c:27`
**Severity:** Informational

**Description:**
```c
if (*(__le32 *) smb->Protocol != SMB1_PROTO_NUMBER) {
```

This cast from `unsigned char Protocol[4]` to `__le32 *` works on all architectures due to `__packed` structs but technically violates strict aliasing rules. Additionally, the error log on line 29 casts `smb->Protocol` to `unsigned int *` which has the same issue.

**Impact:** No practical impact on Linux kernel (compiled with `-fno-strict-aliasing`). Informational only.

---

### P3-6: smberr.h Error Code Overlaps Between ERRDOS and ERRSRV

**File:** `src/include/protocol/smberr.h`
**Severity:** Informational

**Description:**
Several numeric error codes are reused across error classes (ERRDOS and ERRSRV). For example, error code `1` means `ERRbadfunc` in ERRDOS but `ERRerror` in ERRSRV. This is by design per the SMB1 specification (error class + error code form a tuple), but code that only checks the error code without the error class could misinterpret errors. This is a protocol design issue, not a code bug.

**Impact:** No direct security impact; informational note about the protocol.

---

## Positive Observations

1. **AndX Chain Validation (smb1pdu.c:365-406):** The `andx_request_buffer()` function includes three important safety measures: bounds checking against `buf_end`, a forward-progress requirement (`next_ptr <= (char *)andx_ptr`), and a depth limit of 32. This effectively prevents infinite loops on malformed AndX chains.

2. **TRANS2 Buffer Validation Helpers (smb1pdu.c:131-184):** The `smb1_validate_trans2_buffer()` and `smb1_validate_data_offset()` functions use `check_add_overflow()` from `<linux/overflow.h>` for arithmetic overflow protection. These are used consistently in TRANS2 sub-command handlers like `smb_posix_open()`.

3. **Lock Array Bounds Validation (smb1pdu.c:1889-1908):** The locking handler validates that the total number of lock/unlock elements fits within the request buffer, including overflow checking for the count addition and proper element size selection based on `LOCKING_ANDX_LARGE_FILES`.

4. **Echo Handler Hardening (smb1pdu.c:3716-3770):** The echo count is capped at 10 (preventing amplification attacks), and the data count is validated against the response buffer capacity.

5. **FORTIFY_SOURCE Compatibility (smb1pdu.c:120-129):** The `smb1_zero_area()` and `smb1_copy_area()` `noinline` helpers provide a clean solution to the `__fortify_memcpy` warnings for trailing array writes, preserving the runtime safety of FORTIFY_SOURCE for all other code paths.

6. **Path Traversal Protection (smb1pdu.c:844+):** The `smb_get_name()` function delegates to `ksmbd_validate_filename()` for path traversal prevention and also checks veto file lists via `ksmbd_share_veto_filename()`.

7. **Write Handler DataOffset Validation (smb1pdu.c:3653-3665):** The `smb_write_andx()` handler properly validates that `DataOffset` and `DataOffset + count` are within the request buffer bounds before computing the data pointer.

8. **Symlink Protection:** Multiple handlers (`smb_nt_create_andx`, `smb_posix_open`) use `LOOKUP_NO_SYMLINKS` and check `d_is_symlink()` to prevent symlink-following attacks.

9. **Tree Connect Buffer Validation (smb1pdu.c:631-700):** The tree connect handler includes thorough validation of `PasswordLength` against the request buffer, and bounded string parsing for tree name and device type with explicit `buf_end` calculations.

10. **Rename Handler Validation (smb1pdu.c:1020-1030):** The rename handler validates `oldname_len + 2` offset against the request buffer before parsing the new filename, preventing out-of-bounds reads.
