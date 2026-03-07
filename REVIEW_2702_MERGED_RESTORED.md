# KSMBD Gemini Report - Validation Update

Date: 2026-02-27
Scope: Validation of claims in `REVIEW_GEMINI_2702.md` against current source tree and static-analysis logs.

Status labels:
- `REAL` = confirmed defect/risk in current tree
- `FALSE POSITIVE` = claim not valid for current tree/path
- `PARTIAL` = concern exists but original severity/description is inaccurate
- `STYLE` = non-functional quality issue

---

## 1. Validation of Original Gemini Claims

### 2.1 `[CRITICAL]` OOB read in `smb2_write`
**Status**: `FALSE POSITIVE`

The write payload bounds are validated before dispatch in SMB2 generic validation:
- `src/protocol/smb2/smb2misc.c` (`smb2_get_data_area_len`, `smb2_calc_size`, `ksmbd_smb2_check_message`)
- `ksmbd_verify_smb_message()` calls this validation before command handling (`src/protocol/common/smb_common.c`).

For SMB2_WRITE, calculated size uses `DataOffset + Length`, and request is rejected when packet length mismatches.

### 2.2 `[HIGH]` tree connection/share lifetime UAF risk
**Status**: `REAL`

`ksmbd_share_config_put(tree_conn->share_conf)` occurs before final `tree_conn` ref drop in:
- `src/mgmt/tree_connect.c:117`
- `src/mgmt/tree_connect.c:173`

This is a real lifetime-ordering risk under concurrent references.

### 2.3 `[HIGH]` race in `preauth_sess_table`
**Status**: `PARTIAL`

The report overstates call-site locking conditions in session-setup paths, but the list itself is still accessed via lockless helper APIs:
- alloc/lookup helpers in `src/mgmt/user_session.c:424`, `:525`
- lookups also occur in response/signing paths outside explicit conn lock (`src/protocol/smb2/smb2_pdu_common.c`, `src/core/auth.c`).

So the concern is valid as synchronization debt/race risk, but not as strictly described.

### 3.1 `[MEDIUM]` `normalize_path` modifies const input
**Status**: `PARTIAL`

The issue exists only in compatibility branch (`LINUX_VERSION_CODE < 5.6.0`) in `src/core/misc.c`; modern branch (`>=5.6`) does not use this function.

### 3.2 `[MEDIUM]` signing key not scrubbed in `ksmbd_chann_del`
**Status**: `REAL`

`ksmbd_chann_del()` frees channel without clearing `smb3signingkey`:
- `src/mgmt/user_session.c:261`

### 3.3 `[MEDIUM]` preauth session leak on connection teardown
**Status**: `REAL`

`ksmbd_conn_cleanup()` does not drain `conn->preauth_sess_table`:
- alloc/link in `src/mgmt/user_session.c`
- cleanup path in `src/core/connection.c:98`.

### 3.4 `[MEDIUM]` endianness/type mismatches
**Status**: `REAL`

Consistent with sparse warnings:
- `src/protocol/smb2/smb2_query_set.c` (`__le16` assignment from host literal)
- `src/fs/ksmbd_fsctl.c` (`__u64` vs `cpu_to_le64` assignment mismatch).

### 4.1 `[LOW]` duplicate SPDX/header in `smb2_session.c` and `smb2_negotiate.c`
**Status**: `FALSE POSITIVE`

Current files each contain a single SPDX/header block.

### 4.2 `[LOW]` sparse context imbalance in debugfs
**Status**: `PARTIAL` / `STYLE`

The code pattern is complex (`i = -1; break;`) and could confuse analyzers, but no concrete runtime bug was confirmed.

### 5.1 `[CRITICAL]` binary handle hash-key misuse in LSARPC/SAMR
**Status**: `REAL`

Hash tables use `g_str_hash`/`g_str_equal` for binary handles:
- `ksmbd-tools/mountd/rpc_lsarpc.c`
- `ksmbd-tools/mountd/rpc_samr.c`

Keys are raw `handle` byte arrays, not guaranteed NUL-terminated strings.

### 5.2 `[CRITICAL]` IPC size mismatch (tools 64K vs kernel 4K payload)
**Status**: `PARTIAL`

Definition mismatch is real:
- tools: `ksmbd-tools/include/ipc.h` (`KSMBD_IPC_MAX_MESSAGE_SIZE` 64K)
- kernel: `src/include/transport/transport_ipc.h` (`KSMBD_IPC_MAX_PAYLOAD` 4096)

Kernel validates received response payload against 4096 (`src/transport/transport_ipc.c:582`). Impact is functional incompatibility/rejections, not guaranteed kernel hang as originally claimed.

### 5.3 `[HIGH]` one-byte overflow in `base64_decode`
**Status**: `REAL`

`base64_decode()` writes `ret[*dstlen] = 0` after `g_base64_decode()`, which returns binary buffer length `*dstlen`:
- `ksmbd-tools/tools/tools.c:271`

### 5.4 `[HIGH]` password/key memory exposure
**Status**: `PARTIAL`

- Command-line password exposure via `-p` (`optarg`) remains valid operationally.
- Zeroization handling is inconsistent: some paths use `explicit_bzero` (`kill_ksmbd_user`), but update path frees old password without scrub (`usm_update_user_password`).

---

## 2. Corrected Priority (From Gemini Items)

### High
1. `tree_connect` share-config lifetime ordering fix.
2. `preauth_sess_table` synchronization and teardown hardening.
3. `ksmbd-tools` RPC handle hash fix (binary-safe key/hash/equal).
4. `base64_decode` terminator overflow fix.

### Medium
5. scrub `smb3signingkey` in all channel free paths.
6. drain `preauth_sess_table` during connection cleanup.
7. fix sparse endianness/type mismatches.
8. resolve IPC size-contract mismatch between tools/kernel.

### Low
9. simplify debugfs loop style for analyzer clarity.

