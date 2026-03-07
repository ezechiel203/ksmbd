# Part 15: Testability Refactor — Making Production Code Testable

**Date:** 2026-03-03
**Prerequisite for:** All plans in Parts 01-14
**Problem:** 78% of KUnit tests (67/85 files) replicate production logic locally instead
of calling real functions. These tests are **useless** — they test a local copy of the code,
not the actual kernel module. If production code diverges, the test still passes.

---

## Executive Summary

| Metric | Current | After Refactor |
|--------|---------|---------------|
| Test files calling real functions | 18 (21%) | 85+ (100%) |
| Test files with replicated logic only | 67 (79%) | 0 (0%) |
| Static functions with testable pure logic | 136 (untestable) | 0 (all testable) |
| Effective production code test coverage | ~5-10% | ~40-50% |

**Root cause:** 136 static functions implement pure validation, calculation, parsing,
and protocol logic that has clear testable inputs/outputs — but the `static` keyword
prevents test modules from calling them.

**Solution:** The kernel provides `VISIBLE_IF_KUNIT` (since 6.1) and
`EXPORT_SYMBOL_IF_KUNIT` in `<kunit/visibility.h>`:

```c
#include <kunit/visibility.h>

// In production .c file:
VISIBLE_IF_KUNIT
int validate_lock_flags(u32 flags) { ... }
EXPORT_SYMBOL_IF_KUNIT(validate_lock_flags);

// In test .c file:
MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
// Now call validate_lock_flags() directly — real production code!
```

- When `CONFIG_KUNIT` is disabled: `VISIBLE_IF_KUNIT` expands to `static`, zero overhead
- When `CONFIG_KUNIT` is enabled: function is non-static and exported to test namespace
- Tests import the namespace and call real functions

---

## Part A: Functions to Make Testable (136 functions across 14 files)

### A.1: `src/core/auth.c` — 12 functions

These are pure cryptographic and key-derivation functions testable with known vectors.

| # | Function | Lines | Test Value | Current Test |
|---|----------|-------|-----------|-------------|
| 1 | `ksmbd_enc_p24()` | ~10 | DES encryption, RFC test vectors | Replicated in ksmbd_test_auth.c |
| 2 | `ksmbd_enc_md4()` | ~15 | MD4 hashing, RFC 1320 vectors | Replicated in ksmbd_test_md4.c |
| 3 | `ksmbd_enc_update_sess_key()` | ~10 | MD5-based key derivation | Replicated |
| 4 | `cifs_arc4_setkey()` | ~20 | RC4 key schedule | Replicated |
| 5 | `cifs_arc4_crypt()` | ~15 | RC4 stream cipher | Replicated |
| 6 | `ksmbd_gen_sess_key()` | ~20 | HMAC-MD5 key gen | Replicated |
| 7 | `calc_ntlmv2_hash()` | ~30 | NTLMv2 hash, MS test vectors | Replicated |
| 8 | `__ksmbd_auth_ntlmv2()` | ~50 | NTLMv2 verification | Replicated |
| 9 | `generate_key()` | ~25 | SMB3 KDF generation | Replicated |
| 10 | `generate_smb3signingkey()` | ~20 | SMB3 signing key | Replicated |
| 11 | `generate_smb3encryptionkey()` | ~20 | SMB3 encryption key | Replicated |
| 12 | `ksmbd_init_sg()` | ~30 | SG list construction | Not tested |

**Header:** `src/include/core/auth.h` — add 12 declarations inside `#if IS_ENABLED(CONFIG_KUNIT)` guard.

### A.2: `src/core/smb2_compress.c` — 14 functions

ALL compression algorithms are pure functions with zero kernel dependencies.

| # | Function | Lines | Test Value |
|---|----------|-------|-----------|
| 1 | `smb2_pattern_v1_compress()` | ~30 | Pattern compression (MS-XCA §2.1) |
| 2 | `smb2_pattern_v1_decompress()` | ~20 | Pattern decompression |
| 3 | `lznt1_get_offset()` | ~10 | Bit field extraction |
| 4 | `lznt1_get_length()` | ~10 | Bit field extraction |
| 5 | `ksmbd_lznt1_decompress()` | ~60 | LZNT1 decompression (MS-XCA §2.2) |
| 6 | `ksmbd_lznt1_compress()` | ~80 | LZNT1 compression |
| 7 | `ksmbd_lz77_decompress()` | ~50 | LZ77 decompression (MS-XCA §2.3) |
| 8 | `ksmbd_lz77_compress()` | ~70 | LZ77 compression |
| 9 | `ksmbd_lz77huff_decompress()` | ~80 | LZ77+Huffman decompression (MS-XCA §2.4) |
| 10 | `ksmbd_lz77huff_compress()` | ~100 | LZ77+Huffman compression |
| 11 | `smb2_compress_data()` | ~30 | Algorithm dispatcher |
| 12 | `smb2_decompress_data()` | ~40 | Algorithm dispatcher |
| 13 | `smb2_lz4_decompress()` | ~20 | LZ4 wrapper |
| 14 | `odx_nonce_hash()` | ~15 | ODX token hash |

**Header:** Create `src/include/core/smb2_compress.h` — add all 14 declarations.

### A.3: `src/protocol/smb2/smb2_lock.c` — 4 functions

Lock validation and sequence replay are critical security-sensitive logic.

| # | Function | Lines | Test Value |
|---|----------|-------|-----------|
| 1 | `smb2_set_flock_flags()` | ~30 | Flag mapping: SMB lock flags → POSIX flock |
| 2 | `smb2_lock_init()` | ~15 | Lock structure initialization |
| 3 | `check_lock_sequence()` | ~40 | Lock sequence replay detection (MS-SMB2 §3.3.5.14) |
| 4 | `store_lock_sequence()` | ~10 | Sequence storage after success |

**Header:** `src/include/protocol/smb2pdu.h` — add 4 declarations in KUnit guard.

### A.4: `src/protocol/smb2/smb2_create.c` — 4 functions

Create validation and durable handle parsing.

| # | Function | Lines | Test Value |
|---|----------|-------|-----------|
| 1 | `smb2_create_open_flags()` | ~40 | Access + disposition → open flags |
| 2 | `smb_check_parent_dacl_deny()` | ~60 | DACL parent permission check |
| 3 | `smb2_create_sd_buffer()` | ~40 | Security descriptor assembly |
| 4 | `parse_durable_handle_context()` | ~80 | DH/DH2/DHnC/DH2C context parsing |

**Header:** `src/include/protocol/smb2pdu.h` — add 4 declarations.

### A.5: `src/protocol/smb2/smb2_negotiate.c` — 6 functions

Negotiate context decoding — critical for protocol compliance testing.

| # | Function | Lines | Test Value |
|---|----------|-------|-----------|
| 1 | `decode_preauth_ctxt()` | ~30 | Preauth hash ID validation |
| 2 | `decode_encrypt_ctxt()` | ~40 | Encryption cipher negotiation |
| 3 | `decode_compress_ctxt()` | ~30 | Compression algorithm validation |
| 4 | `decode_sign_cap_ctxt()` | ~25 | Signing algorithm validation |
| 5 | `deassemble_neg_contexts()` | ~60 | Full negotiate context pipeline |
| 6 | `assemble_neg_contexts()` | ~80 | Negotiate response construction |

**Header:** `src/include/protocol/smb2pdu.h` — add 6 declarations.

### A.6: `src/protocol/smb2/smb2_pdu_common.c` — 3 functions

Compound request and encryption helpers.

| # | Function | Lines | Test Value |
|---|----------|-------|-----------|
| 1 | `init_chained_smb2_rsp()` | ~60 | Compound FID propagation (MS-SMB2 §3.3.5.2.7.2) |
| 2 | `ksmbd_gcm_nonce_limit_reached()` | ~10 | GCM nonce counter check |
| 3 | `fill_transform_hdr()` | ~30 | Encryption header assembly |

**Header:** `src/include/protocol/smb2pdu.h` — add 3 declarations.

### A.7: `src/protocol/smb2/smb2_session.c` — 5 functions

Session setup and authentication blob parsing.

| # | Function | Lines | Test Value |
|---|----------|-------|-----------|
| 1 | `generate_preauth_hash()` | ~20 | Preauth hash chain computation |
| 2 | `decode_negotiation_token()` | ~30 | SPNEGO token parsing |
| 3 | `ntlm_negotiate()` | ~40 | NTLM message 1 validation |
| 4 | `user_authblob()` | ~30 | Auth blob extraction |
| 5 | `ntlm_authenticate()` | ~80 | NTLM message 3 verification |

**Header:** `src/include/protocol/smb2pdu.h` — add 5 declarations.

### A.8: `src/protocol/smb2/smb2_query_set.c` — 17 functions

Info-level query handlers — pure response assembly.

| # | Function | Lines | Test Value |
|---|----------|-------|-----------|
| 1 | `buffer_check_err()` | ~15 | Buffer boundary validation |
| 2 | `get_standard_info_pipe()` | ~15 | Pipe standard info response |
| 3 | `get_internal_info_pipe()` | ~10 | Pipe internal info response |
| 4 | `get_file_access_info()` | ~10 | Access info response |
| 5 | `get_file_basic_info()` | ~20 | Basic info response |
| 6 | `get_file_standard_info()` | ~15 | Standard info response |
| 7 | `get_file_alignment_info()` | ~10 | Alignment info response |
| 8 | `get_file_internal_info()` | ~10 | Internal info response |
| 9 | `get_file_ea_info()` | ~10 | EA info response |
| 10 | `get_file_position_info()` | ~10 | Position info response |
| 11 | `get_file_mode_info()` | ~10 | Mode info response |
| 12 | `get_file_compression_info()` | ~15 | Compression info response |
| 13 | `get_file_attribute_tag_info()` | ~10 | Attribute tag response |
| 14 | `get_file_id_info()` | ~10 | File ID response |
| 15 | `fill_fallback_object_id()` | ~10 | Object ID generation |
| 16 | `set_file_position_info()` | ~15 | Seek offset validation |
| 17 | `set_file_mode_info()` | ~10 | Mode setting |

**Header:** Create `src/include/protocol/smb2_query_set.h` or add to `smb2pdu.h`.

### A.9: `src/fs/oplock.c` — 12 functions

Oplock/lease state machine — critical for caching correctness.

| # | Function | Lines | Test Value |
|---|----------|-------|-----------|
| 1 | `alloc_lease()` | ~20 | Lease context initialization |
| 2 | `lease_none_upgrade()` | ~30 | Lease state transitions |
| 3 | `grant_write_oplock()` | ~15 | Write oplock level assignment |
| 4 | `grant_read_oplock()` | ~15 | Read oplock level assignment |
| 5 | `grant_none_oplock()` | ~10 | None oplock assignment |
| 6 | `compare_guid_key()` | ~20 | Client GUID matching |
| 7 | `same_client_has_lease()` | ~25 | Client lease ownership |
| 8 | `oplock_break_pending()` | ~10 | Break pending check |
| 9 | `oplock_break()` | ~100 | Core break state machine |
| 10 | `set_oplock_level()` | ~20 | Level setting |
| 11 | `copy_lease()` | ~15 | Lease structure copy |
| 12 | `add_lease_global_list()` | ~15 | Global lease tracking |

**Header:** `src/include/fs/oplock.h` — add 12 declarations.

### A.10: `src/fs/smbacl.c` — 10 functions

ACL parsing and conversion — security-critical.

| # | Function | Lines | Test Value |
|---|----------|-------|-----------|
| 1 | `smb_copy_sid()` | ~10 | SID structure copy |
| 2 | `access_flags_to_mode()` | ~20 | SMB ACE → Unix mode |
| 3 | `mode_to_access_flags()` | ~20 | Unix mode → SMB ACE |
| 4 | `ksmbd_ace_size()` | ~5 | ACE size calculation |
| 5 | `fill_ace_for_sid()` | ~30 | ACE construction |
| 6 | `parse_dacl()` | ~60 | DACL parsing |
| 7 | `parse_sid()` | ~20 | SID parsing from binary |
| 8 | `smb_set_ace()` | ~15 | ACE field setting |
| 9 | `smb_check_parent_dacl_deny()` | ~60 | Parent DACL check |
| 10 | `smb2_create_sd_buffer()` | ~40 | SD assembly |

**Header:** `src/include/fs/smbacl.h` — add 10 declarations.

### A.11: `src/fs/vfs_cache.c` — 6 functions

File handle and inode management.

| # | Function | Lines | Test Value |
|---|----------|-------|-----------|
| 1 | `fd_limit_depleted()` | ~5 | Limit check |
| 2 | `inode_hash()` | ~5 | Pure hash computation |
| 3 | `ksmbd_inode_init()` | ~20 | Inode structure setup |
| 4 | `__sanity_check()` | ~15 | File state validation |
| 5 | `is_reconnectable()` | ~20 | Durable handle check |
| 6 | `get_file_object_id_info()` | ~15 | Object ID response |

**Header:** `src/include/fs/vfs_cache.h` — add 6 declarations.

### A.12: `src/fs/ksmbd_fsctl.c` — 7 functions

FSCTL helpers with testable logic.

| # | Function | Lines | Test Value |
|---|----------|-------|-----------|
| 1 | `ksmbd_fsctl_build_fallback_object_id()` | ~15 | Object ID generation |
| 2 | `ksmbd_fsctl_fill_object_id_rsp()` | ~20 | Object ID response |
| 3 | `fsctl_is_pathname_valid_handler()` | ~15 | Path validation |
| 4 | `fsctl_idev_ipv4_address()` | ~20 | IPv4 address extraction |
| 5 | `fsctl_copychunk_common()` | ~80 | Copy chunk validation |
| 6 | `odx_nonce_hash()` | ~15 | Hash calculation |
| 7 | `odx_token_validate()` | ~20 | Token lifetime validation |

**Header:** `src/include/fs/ksmbd_fsctl.h` — add 7 declarations.

### A.13: Build infrastructure (41 inline functions)

Small helpers (< 10 lines) that should move from .c files to .h files as `static inline`:

| Source File | Functions | Target Header |
|------------|----------|---------------|
| smb2_negotiate.c | `build_preauth_ctxt`, `build_encrypt_ctxt`, `build_compress_ctxt`, `build_sign_cap_ctxt`, `build_rdma_transform_ctxt`, `build_transport_cap_ctxt`, `build_posix_ctxt` (7) | smb2pdu.h |
| auth.c | `smb2_sg_set_buf` (1) | auth.h |
| oplock.c | `fruit_rsp_size` (1) | oplock.h |
| smb2_lock.c | `lock_defer_pending` (1) | smb2pdu.h |

These don't need `VISIBLE_IF_KUNIT` — as `static inline` in headers, they're always available.

---

## Part B: Production Code Changes

### B.1: Pattern for each function

**Before:**
```c
// src/protocol/smb2/smb2_lock.c
static int check_lock_sequence(struct ksmbd_file *fp, u32 lock_seq_val)
{
    ...
}
```

**After:**
```c
// src/protocol/smb2/smb2_lock.c
#include <kunit/visibility.h>

VISIBLE_IF_KUNIT
int check_lock_sequence(struct ksmbd_file *fp, u32 lock_seq_val)
{
    ...
}
EXPORT_SYMBOL_IF_KUNIT(check_lock_sequence);
```

**Header addition:**
```c
// src/include/protocol/smb2pdu.h
#if IS_ENABLED(CONFIG_KUNIT)
int check_lock_sequence(struct ksmbd_file *fp, u32 lock_seq_val);
int store_lock_sequence(struct ksmbd_file *fp, u32 lock_seq_val);
int smb2_set_flock_flags(struct file_lock *flock, unsigned int flags);
int smb2_lock_init(struct file_lock *flock, struct file *file, ...);
#endif
```

### B.2: File-by-file change list

| # | Production File | Changes | Functions |
|---|----------------|---------|-----------|
| 1 | `src/core/auth.c` | Add `#include <kunit/visibility.h>`, replace `static` with `VISIBLE_IF_KUNIT` on 12 functions, add `EXPORT_SYMBOL_IF_KUNIT()` after each | 12 |
| 2 | `src/core/smb2_compress.c` | Same pattern for 14 functions | 14 |
| 3 | `src/protocol/smb2/smb2_lock.c` | Same pattern for 4 functions | 4 |
| 4 | `src/protocol/smb2/smb2_create.c` | Same pattern for 4 functions | 4 |
| 5 | `src/protocol/smb2/smb2_negotiate.c` | Same pattern for 6 functions | 6 |
| 6 | `src/protocol/smb2/smb2_pdu_common.c` | Same pattern for 3 functions | 3 |
| 7 | `src/protocol/smb2/smb2_session.c` | Same pattern for 5 functions | 5 |
| 8 | `src/protocol/smb2/smb2_query_set.c` | Same pattern for 17 functions | 17 |
| 9 | `src/fs/oplock.c` | Same pattern for 12 functions | 12 |
| 10 | `src/fs/smbacl.c` | Same pattern for 10 functions | 10 |
| 11 | `src/fs/vfs_cache.c` | Same pattern for 6 functions | 6 |
| 12 | `src/fs/ksmbd_fsctl.c` | Same pattern for 7 functions | 7 |
| | **Total production changes** | | **106** |

Plus 30 inline functions moved to headers (no `VISIBLE_IF_KUNIT` needed).

### B.3: Header changes

| # | Header File | New Declarations |
|---|------------|-----------------|
| 1 | `src/include/core/auth.h` | 12 function declarations in `#if IS_ENABLED(CONFIG_KUNIT)` |
| 2 | `src/include/core/smb2_compress.h` (NEW) | 14 function declarations |
| 3 | `src/include/protocol/smb2pdu.h` | 22 function declarations (lock + create + negotiate + pdu_common + session) |
| 4 | `src/include/fs/oplock.h` | 12 function declarations |
| 5 | `src/include/fs/smbacl.h` | 10 function declarations |
| 6 | `src/include/fs/vfs_cache.h` | 6 function declarations |
| 7 | `src/include/fs/ksmbd_fsctl.h` | 7 function declarations |

---

## Part C: Test File Rewrites (67 files)

Every replicated test file must be rewritten to call real production functions.

### C.1: Pattern for test file conversion

**Before (replicated — USELESS):**
```c
// test/ksmbd_test_smb2_lock.c
/* ---- Replicated constants ---- */
#define TEST_SMB2_LOCKFLAG_SHARED      0x0001
#define TEST_KSMBD_MAX_LOCK_COUNT      64

/* ---- Replicated logic ---- */
static int test_validate_lock_flags(u32 flags)
{
    // LOCAL COPY of smb2_lock.c logic — NOT testing real code!
    bool shared = !!(flags & TEST_SMB2_LOCKFLAG_SHARED);
    ...
}

static void test_lock_flags_valid_shared(struct kunit *test)
{
    KUNIT_EXPECT_EQ(test, test_validate_lock_flags(0x0001), 0);
}
```

**After (real calls — USEFUL):**
```c
// test/ksmbd_test_smb2_lock.c
#include <kunit/test.h>
#include <kunit/visibility.h>
#include "smb2pdu.h"       // Real production header
#include "vfs_cache.h"     // For struct ksmbd_file

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

static void test_lock_flags_valid_shared(struct kunit *test)
{
    struct file_lock flock = {};
    int ret;

    // Call REAL production function
    ret = smb2_set_flock_flags(&flock, SMB2_LOCKFLAG_SHARED);
    KUNIT_EXPECT_EQ(test, ret, 0);
    KUNIT_EXPECT_TRUE(test, flock.c.flc_type == F_RDLCK);
}

static void test_lock_sequence_replay(struct kunit *test)
{
    struct ksmbd_file fp = {};
    int ret;

    // Initialize lock_seq array with sentinel
    memset(fp.lock_seq, 0xFF, sizeof(fp.lock_seq));

    // Call REAL check_lock_sequence
    ret = check_lock_sequence(&fp, 0x35);
    KUNIT_EXPECT_NE(test, ret, 0); // First time: not a replay

    // Store sequence after success
    store_lock_sequence(&fp, 0x35);

    // Same sequence again: should detect replay
    ret = check_lock_sequence(&fp, 0x35);
    KUNIT_EXPECT_EQ(test, ret, 0); // Replay detected → success
}
```

### C.2: Complete rewrite list (67 files)

**Priority 1 — High-value protocol tests (14 files):**

| # | Test File | Replicated Functions to Remove | Real Functions to Call |
|---|----------|-------------------------------|----------------------|
| 1 | `ksmbd_test_smb2_lock.c` | `test_validate_lock_flags`, `test_validate_lock_count`, `test_lock_array_fits`, `test_validate_lock_range`, `test_calc_fl_end`, `test_range_beyond_offset_max`, `test_ranges_overlap`, `test_extract_lock_sequence`, `test_check_lock_replay` | `smb2_set_flock_flags`, `smb2_lock_init`, `check_lock_sequence`, `store_lock_sequence` |
| 2 | `ksmbd_test_smb2_create.c` | `test_create_open_flags`, `test_validate_access_mask`, `test_validate_create_options`, `test_validate_impersonation`, `test_validate_name_length` | `smb2_create_open_flags`, `parse_durable_handle_context`, `smb_check_parent_dacl_deny` |
| 3 | `ksmbd_test_smb2_negotiate.c` | `test_select_dialect`, `test_validate_neg_ctx_*` | `decode_preauth_ctxt`, `decode_encrypt_ctxt`, `decode_compress_ctxt`, `decode_sign_cap_ctxt`, `deassemble_neg_contexts` |
| 4 | `ksmbd_test_smb2_session.c` | `test_preauth_*`, `test_ntlm_*` | `generate_preauth_hash`, `decode_negotiation_token`, `ntlm_negotiate`, `ntlm_authenticate` |
| 5 | `ksmbd_test_smb2_compound.c` | `test_init_chained_rsp`, `test_fid_*` | `init_chained_smb2_rsp` |
| 6 | `ksmbd_test_smb2_read_write.c` | `test_validate_read_*`, `test_validate_write_*` | (no pure-logic statics in this file — tests should stay integration-style via VM) |
| 7 | `ksmbd_test_compress.c` | ALL `test_pattern_v1_*`, `test_lznt1_*`, `test_lz77_*`, `test_lz77huff_*` | `smb2_pattern_v1_compress/decompress`, `ksmbd_lznt1_compress/decompress`, `ksmbd_lz77_compress/decompress`, `ksmbd_lz77huff_compress/decompress`, `smb2_compress_data`, `smb2_decompress_data` |
| 8 | `ksmbd_test_oplock.c` | `test_lease_*`, `test_oplock_*` | `alloc_lease`, `lease_none_upgrade`, `grant_write_oplock`, `grant_read_oplock`, `oplock_break`, `set_oplock_level` |
| 9 | `ksmbd_test_acl.c` | `test_ace_*`, `test_dacl_*`, `test_sid_*` | `smb_copy_sid`, `access_flags_to_mode`, `mode_to_access_flags`, `ksmbd_ace_size`, `fill_ace_for_sid`, `parse_dacl`, `parse_sid` |
| 10 | `ksmbd_test_smb2_query_set.c` | `test_get_file_*`, `test_set_file_*` | `buffer_check_err`, `get_file_basic_info`, `get_file_standard_info`, `set_file_position_info`, etc. |
| 11 | `ksmbd_test_auth.c` | `test_des_*`, `test_md4_*`, `test_ntlmv2_*` | `ksmbd_enc_p24`, `ksmbd_enc_md4`, `calc_ntlmv2_hash`, `generate_key` |
| 12 | `ksmbd_test_connection.c` | `test_conn_*` | (most connection functions already non-static — verify and use) |
| 13 | `ksmbd_test_fsctl_dispatch.c` | `test_fsctl_*` | `fsctl_copychunk_common`, `odx_token_validate`, `ksmbd_fsctl_build_fallback_object_id` |
| 14 | `ksmbd_test_smb2_ioctl.c` | `test_ioctl_*` | (IOCTL dispatch is VFS-heavy — keep VM integration tests for most) |

**Priority 2 — Info/query/FSCTL tests (23 files):**

| Range | Files | Pattern |
|-------|-------|---------|
| `ksmbd_test_info_file.c` | 65 local → ~15 real calls to `get_file_*_info` | Call real info-level handlers |
| `ksmbd_test_info_file_set.c` | 17 local → real `set_file_*_info` calls | Call real set handlers |
| `ksmbd_test_info_fs.c` | 16 local → real FS info handlers | Call real handlers |
| `ksmbd_test_info_quota.c` | 7 local → real quota handlers | Call real handlers |
| `ksmbd_test_info_security.c` | 6 local → real security handlers | Call real handlers |
| `ksmbd_test_info_dispatch.c` | 23 local → real dispatch function | Call real dispatch |
| `ksmbd_test_fsctl_copychunk.c` | 24 local → `fsctl_copychunk_common` | Call real copychunk validation |
| `ksmbd_test_fsctl_sparse.c` | 27 local → real sparse handlers | Where possible |
| `ksmbd_test_fsctl_object_id.c` | 20 local → `ksmbd_fsctl_build_fallback_object_id` | Call real OID gen |
| `ksmbd_test_fsctl_odx.c` | 17 local → `odx_nonce_hash`, `odx_token_validate` | Call real ODX functions |
| `ksmbd_test_fsctl_validate_negotiate.c` | 14 local → real validate negotiate | Call real function |
| `ksmbd_test_fsctl_compression.c` | 13 local → real compress functions | Call real compress/decompress |
| `ksmbd_test_fsctl_duplicate.c` | 16 local → real duplicate extent validation | Where possible |
| `ksmbd_test_fsctl_integrity.c` | 11 local → real integrity functions | Where possible |
| `ksmbd_test_fsctl_misc.c` | 24 local → real misc FSCTL handlers | Where possible |
| `ksmbd_test_fsctl_pipe.c` | 15 local → real pipe functions | Where possible |
| `ksmbd_test_fsctl_volume.c` | 14 local → real volume functions | Where possible |
| `ksmbd_test_create_ctx.c` | 30 local → real context parsing | Where possible |
| `ksmbd_test_create_ctx_tags.c` | 17 local → real tag validation | Where possible |
| `ksmbd_test_credit.c` | 14 local → (credit calc is simple inline) | Keep or inline |
| `ksmbd_test_pdu_common.c` | 26 local → `init_chained_smb2_rsp`, `fill_transform_hdr` | Call real functions |
| `ksmbd_test_smb2_misc.c` | 34 local → real misc helpers | Where possible |
| `ksmbd_test_smb2_dispatch.c` | 30 local → real dispatch | Where possible |

**Priority 3 — Remaining files (30 files):**

| Range | Files | Notes |
|-------|-------|-------|
| SMB1: `ksmbd_test_smb1_cmds.c`, `ksmbd_test_smb1_ops.c`, `ksmbd_test_smb1_parser.c`, `ksmbd_test_negotiate.c` | 4 files, ~121 local functions | SMB1 functions are largely static; prioritize VM integration tests |
| Encoding: `ksmbd_test_asn1.c`, `ksmbd_test_ndr.c`, `ksmbd_test_unicode.c` | 3 files, ~119 local functions | Many encoding functions are already non-static — verify and convert |
| Management: `ksmbd_test_tree_connect.c`, `ksmbd_test_user_session_mgmt.c`, `ksmbd_test_witness.c` | 3 files, ~73 local functions | Management functions often non-static |
| Features: `ksmbd_test_dfs.c`, `ksmbd_test_resilient.c`, `ksmbd_test_rsvd.c`, `ksmbd_test_quota.c` | 4 files, ~109 local functions | Feature-specific |
| Core: `ksmbd_test_server.c`, `ksmbd_test_work.c`, `ksmbd_test_buffer.c`, `ksmbd_test_ida.c`, `ksmbd_test_hooks.c`, `ksmbd_test_ipc.c`, `ksmbd_test_notify.c` | 7 files, ~196 local functions | Core infrastructure |
| Protocol: `ksmbd_test_smb2_cancel.c`, `ksmbd_test_smb2_dir.c`, `ksmbd_test_smb2_notify.c`, `ksmbd_test_smb2_ops.c`, `ksmbd_test_smb2_tree.c` | 5 files, ~172 local functions | SMB2 command-specific |
| FS: `ksmbd_test_branchcache.c`, `ksmbd_test_app_instance.c`, `ksmbd_test_quic.c`, `ksmbd_test_netmisc.c` | 4 files, ~132 local functions | FS features |

---

## Part D: Functions That Must Stay Replicated

Some functions genuinely cannot be made testable because they require VFS, socket, or
workqueue infrastructure that doesn't exist in a KUnit context. These are the **only**
acceptable cases for replicated logic:

| Category | Count | Reason | Alternative Testing |
|----------|-------|--------|-------------------|
| VFS file operations | ~80 | Require open file descriptors, mount points | VM integration tests |
| Socket/transport ops | ~30 | Require network sockets | VM integration tests |
| Workqueue handlers | ~50 | Require ksmbd_work structures with connections | VM integration tests |
| Timer/thread callbacks | ~20 | Require running kernel threads | VM integration tests |
| Memory allocator wrappers | ~15 | Thin wrappers around kmalloc/kfree | Not worth testing directly |
| **Total** | **~195** | | **VM integration tests** |

For these 195 functions, the testing strategy is:
1. **Do NOT replicate** their logic in KUnit tests (that's useless)
2. **Test via VM integration scripts** (`tests/ksmbd_concurrency_test.sh`, `tests/ksmbd_stress_test.sh`, smbtorture)
3. **Test the functions they call** (the 136 VISIBLE_IF_KUNIT functions) to verify the logic

---

## Part E: Implementation Steps

### Step 1: Add `<kunit/visibility.h>` infrastructure
- Verify `kunit/visibility.h` exists in build kernel headers (confirmed: 6.18.13-arch1-1)
- Add `#include <kunit/visibility.h>` to all 12 production .c files listed in B.2

### Step 2: Convert 136 functions (batch by file)
For each file in A.1-A.12:
1. Replace `static` with `VISIBLE_IF_KUNIT` on each function
2. Add `EXPORT_SYMBOL_IF_KUNIT(func_name);` after each function body
3. Add declaration to appropriate header inside `#if IS_ENABLED(CONFIG_KUNIT)` guard

### Step 3: Move 41 inline functions to headers
Move small helper functions from .c files to .h files as `static inline`.

### Step 4: Rewrite 67 test files (batch by priority)
For each test file in C.2:
1. Remove all `test_` prefixed local functions that mirror production logic
2. Remove all `TEST_` prefixed local constants
3. Add `#include` of real production headers
4. Add `MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");`
5. Rewrite test cases to call real production functions
6. Keep test structure (KUNIT_CASE, kunit_suite, etc.)

### Step 5: Update test/Makefile
No new .o files needed — existing test files are being rewritten in-place.

### Step 6: Build verification
```bash
# With KUnit enabled (tests call real functions):
make KDIR=/lib/modules/6.18.13-arch1-1/build EXTERNAL_SMBDIRECT=n \
     CONFIG_KSMBD_KUNIT_TEST=y all

# Without KUnit (functions stay static, zero overhead):
make KDIR=/lib/modules/6.18.13-arch1-1/build EXTERNAL_SMBDIRECT=n all
```

### Step 7: Verify no production behavior change
- Load ksmbd.ko on VM
- Run full smbtorture sweep
- Verify identical results before and after refactor

---

## Part F: Impact on Plans 01-14

All previous test plans (Parts 01-14) assumed replicated logic was acceptable. After
this refactor:

1. **Plans 01-07**: New KUnit tests should call real functions via `MODULE_IMPORT_NS`
2. **Plan 10 (edge cases)**: Edge case tests now test real production code paths
3. **Plan 11 (stress tests)**: VM integration — unaffected
4. **Plan 12 (coverage)**: Coverage jumps from ~5-10% to ~40-50% after refactor
5. **Plan 13 (compliance)**: Protocol compliance tests now verify real implementations
6. **Plan 14 (concurrency/error/regression)**: Regression tests now test real bug fixes

**Key rule for all future tests:**
> Every KUnit test MUST call at least one real production function.
> Tests that only exercise local `test_` helper functions are BANNED.
> Use `MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING")` in every test file.

---

## Part G: Verification Criteria

### Build must pass both ways:
1. `CONFIG_KSMBD_KUNIT_TEST=y` — functions non-static, tests call real code
2. `CONFIG_KSMBD_KUNIT_TEST` not set — functions remain static, no overhead

### No replicated logic allowed:
- `grep -r "Replicated" test/ksmbd_test_*.c` must return empty
- `grep -rn "^static.*test_" test/ksmbd_test_*.c` must only match KUnit test functions (not replicated helpers)

### Test function naming convention:
- `test_<subsystem>_<scenario>` — KUnit test function (calls real production code)
- NO `test_validate_*`, `test_calc_*`, `test_check_*` local helpers allowed

### Coverage metric:
- Before: 18/85 files call real functions (21%)
- After: 85/85 files call real functions (100%)
- Before: ~5-10% production code path coverage
- After: ~40-50% production code path coverage
