# Audit Userspace Rpc Tests

Agent ID: a60ee8bc4595a86c8

Now I have a comprehensive understanding of all the test files and the implementation. Here is my full audit report.

---

# RPC Test File Audit Report Against Protocol Specifications

## Methodology

Each test file was reviewed against the following specifications:
- **MS-RPCE** (DCE/RPC): PDU types, header layout, UUID encoding, NDR transfer syntax
- **MS-SRVSVC**: NetShareEnumAll (opnum 15), NetShareGetInfo (opnum 16), interface UUID
- **MS-WKSS**: NetWkstaGetInfo (opnum 0), interface UUID
- **MS-SAMR**: SamrConnect5 (64), SamrEnumDomains (6), SamrLookupDomain (5), SamrOpenDomain (7), SamrLookupNames (17), SamrOpenUser (34), SamrQueryUserInfo (36), SamrQuerySecurity (3), SamrGetGroupsForUser (39), SamrGetAliasMembership (16), SamrCloseHandle (1)
- **MS-LSAD**: LsarOpenPolicy2 (44), LsarQueryInformationPolicy (7), LsarLookupSids2 (57), LsarLookupNames3 (68), LsarClose (0)
- **MS-DSSP**: DsRoleGetPrimaryDomainInformation (opnum 0), UUID 3919286a-b10c-11d0-9ba8-00c04fd92ef5

---

## 1. `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_rpc_pipe.c`

### DCE/RPC PDU Type Constants

| Constant | Value in Code | Spec Value (MS-RPCE 12.6.3.1) | Verdict |
|---|---|---|---|
| DCERPC_PTYPE_RPC_BIND | 0x0B (11) | 11 | **CORRECT** |
| DCERPC_PTYPE_RPC_BINDACK | 0x0C (12) | 12 | **CORRECT** |
| DCERPC_PTYPE_RPC_BINDNACK | 0x0D (13) | 13 | **CORRECT** |
| DCERPC_PTYPE_RPC_REQUEST | 0x00 (0) | 0 | **CORRECT** |
| DCERPC_PTYPE_RPC_RESPONSE | 0x02 (2) | 2 | **CORRECT** |
| DCERPC_PTYPE_RPC_ALTCONT | 0x0E (14) | 14 | **CORRECT** |
| DCERPC_PTYPE_RPC_ALTCONTRESP | 0x0F (15) | 15 | **CORRECT** |
| DCERPC_PTYPE_RPC_PING | 0x01 (1) | 1 | **CORRECT** |

### DCE/RPC PFC Flags

| Flag | Value in Code | Spec Value | Verdict |
|---|---|---|---|
| DCERPC_PFC_FIRST_FRAG | 0x01 | 0x01 | **CORRECT** |
| DCERPC_PFC_LAST_FRAG | 0x02 | 0x02 | **CORRECT** |

### NDR Transfer Syntax UUID

Code: `8a885d04-1ceb-11c9-9fe8-08002b104860` v2.0
Spec (MS-RPCE 2.2.4.11): `8a885d04-1ceb-11c9-9fe8-08002b104860` v2.0
**CORRECT**

### Service Interface UUIDs

| Service | UUID in Code | Spec UUID | Version in Code | Spec Version | Verdict |
|---|---|---|---|---|---|
| SRVSVC | `4b324fc8-1670-01d3-1278-5a47bf6ee188` | `4b324fc8-1670-01d3-1278-5a47bf6ee188` | v3.0 | v3.0 | **CORRECT** |
| WKSSVC | `6bffd098-a112-3610-9833-46c3f87e345a` | `6bffd098-a112-3610-9833-46c3f87e345a` | v1.0 | v1.0 | **CORRECT** |
| SAMR | `12345778-1234-abcd-ef00-0123456789ac` | `12345778-1234-abcd-ef00-0123456789ac` | v1.0 | v1.0 | **CORRECT** |
| LSARPC | `12345778-1234-abcd-ef00-0123456789ab` | `12345778-1234-abcd-ef00-0123456789ab` | v0.0 | v0.0 | **CORRECT** |
| dssetup | `3919286a-b10c-11d0-9ba8-00c04fd92ef5` | `3919286a-b10c-11d0-9ba8-00c04fd92ef5` | v0.0 | v0.0 | **CORRECT** |

### DCE/RPC Header Layout (build_bind_pdu)

Per MS-RPCE 12.6.4.3 (co_bind), the BIND PDU header is:
```
rpc_vers      (1 byte)   = 5
rpc_vers_minor(1 byte)   = 0
ptype         (1 byte)   = 11 (bind)
pfc_flags     (1 byte)   = FIRST|LAST
packed_drep   (4 bytes)  = {0x10, 0, 0, 0} for little-endian
frag_length   (2 bytes LE)
auth_length   (2 bytes LE)
call_id       (4 bytes LE)
max_xmit_frag (2 bytes LE)
max_recv_frag (2 bytes LE)
assoc_group_id(4 bytes LE)
p_context_list (variable)
```

Code builds this as 16-byte header + 2+2+4 bind fields + context list. **CORRECT**.

### Test-by-test Review

| Test | What it tests | Verdict |
|---|---|---|
| `test_rpc_open_close_lifecycle` | Pipe open/close lifecycle | **CORRECT** (implementation test, not protocol-specific) |
| `test_rpc_open_collision` | Double-open returns EEXIST | **CORRECT** |
| `test_rpc_close_nonexistent` | Close non-existent pipe | **CORRECT** |
| `test_rpc_open_multiple_pipes` | Multiple pipe handles | **CORRECT** |
| `test_rpc_destroy_clears_pipes` | rpc_destroy cleanup | **CORRECT** |
| `test_rpc_restricted_context_*` (3 tests) | Anonymous access control | **CORRECT** |
| `test_rpc_write_no_pipe` | Write without open pipe | **CORRECT** |
| `test_rpc_read_no_pipe` | Read without open pipe | **CORRECT** |
| `test_rpc_write_return_ready_bypass` | RETURN_READY fast-path | **CORRECT** |
| `test_rpc_write_unsupported_ptype` | Unsupported PDU type rejected | **CORRECT** |
| `test_rpc_ioctl_payload_too_small` | Payload < header size rejected | **CORRECT** |
| `test_dcerpc_write_headers` | Response header construction | **CORRECT** -- verifies rpc_vers=5, vers_minor=0, ptype=RESPONSE(2), pfc=FIRST|LAST |
| `test_dcerpc_write_headers_emore_data` | EMORE_DATA sets only FIRST_FRAG | **CORRECT** per MS-RPCE fragmentation rules |
| `test_dcerpc_write_headers_resp_fields` | Response header alloc_hint and cancel_count | **CORRECT** |
| `test_rpc_init_destroy_idempotent` | Idempotent init/destroy | **CORRECT** |
| `test_rpc_srvsvc_bind_roundtrip` | SRVSVC BIND -> BIND_ACK | **CORRECT** |
| `test_rpc_wkssvc_bind_roundtrip` | WKSSVC BIND -> BIND_ACK | **CORRECT** |
| `test_rpc_samr_bind_roundtrip` | SAMR BIND -> BIND_ACK | **CORRECT** |
| `test_rpc_lsarpc_bind_roundtrip` | LSARPC BIND -> BIND_ACK | **CORRECT** |
| `test_rpc_bind_nack_unsupported_syntax` | BIND with bogus transfer syntax -> BIND_NACK | **CORRECT** per MS-RPCE 12.6.4.4 |
| `test_rpc_altcont_bind` | ALTER_CONTEXT -> ALTER_CONTEXT_RESP | **CORRECT** per MS-RPCE 12.6.4.6 |
| `test_rpc_bind_dssetup_detection` | Two-context BIND (lsarpc + dssetup) | **CORRECT** |
| `test_rpc_bind_assoc_group_preserved` | assoc_group_id echo in BIND_ACK | **CORRECT** per MS-RPCE 12.6.4.4 (server returns same assoc_group_id) |
| `test_dcerpc_set_ext_payload` | External payload setup | **CORRECT** (implementation test) |
| `test_rpc_pipe_reset_*` (2 tests) | Pipe reset safety | **CORRECT** (implementation test) |
| `test_ndr_write_union_int16_roundtrip` | NDR non-encapsulated union: value written twice | **CORRECT** per MS-RPCE NDR union encoding (discriminant + arm, same value) |
| `test_ndr_write_union_int32_roundtrip` | Same for int32 | **CORRECT** |
| `test_ndr_read_union_int32_roundtrip` | Read back union int32 | **CORRECT** |
| `test_ndr_read_union_int32_mismatch` | Mismatch discriminant/arm returns EINVAL | **CORRECT** -- discriminant must match arm value |
| `test_ndr_write_vstring` | Conformant varying string encoding | **CORRECT** (see detailed analysis below) |
| `test_ndr_write_vstring_null` | NULL -> empty string | **CORRECT** |
| `test_ndr_write_lsa_string` | LSA string encoding | **CORRECT** -- max_count=strlen+1 (includes terminator), actual_count=strlen (excludes terminator) |
| `test_ndr_write_lsa_string_null` | NULL -> max_count=1, actual_count=0 | **CORRECT** |
| `test_ndr_read_vstring_roundtrip` | Write then read vstring | **CORRECT** |
| `test_ndr_read_vstring_empty` | Empty string vstring | **CORRECT** |
| `test_ndr_read_vstring_truncated` | Truncated payload handling | **CORRECT** |
| `test_ndr_read_vstring_actual_exceeds_max` | actual_count > max_count rejected | **CORRECT** per MS-RPCE NDR rules |
| `test_ndr_read_vstring_ptr` | vstring pointer read | **CORRECT** |
| `test_ndr_read_uniq_vstring_ptr_with_ref` | Unique pointer with ref_id | **CORRECT** |
| `test_ndr_read_uniq_vstring_ptr_null_ref` | Null unique pointer (ref_id=0) | **CORRECT** |
| `test_ndr_read_ptr` | Raw pointer read | **CORRECT** |
| `test_ndr_read_uniq_ptr` | Unique pointer with ref_id + value | **CORRECT** |
| `test_ndr_read_uniq_ptr_null` | Null unique pointer | **CORRECT** |
| `test_ndr_free_vstring_ptr` | Free helper | **CORRECT** |
| `test_ndr_free_uniq_vstring_ptr` | Free helper | **CORRECT** |
| `test_ndr_read_int*_overflow` (4 tests) | Buffer overflow detection | **CORRECT** |
| `test_ndr_read_int*_null_value` (2 tests) | NULL output pointer handling | **CORRECT** |

### Detailed NDR String Analysis

**`test_ndr_write_string`** tests `ndr_write_string("Hi")`:
- Implementation: max_count = strlen("Hi") = 2, offset = 0, actual_count = 2, followed by UTF-16LE data
- Per MS-RPCE: For a `conformant_and_varying_string`, max_count is the maximum number of **elements** (not including terminator when using `ndr_write_string`). The code uses `strlen(str)` for both max_count and actual_count.

**QUESTIONABLE**: Per strict NDR conformant-varying string rules (MS-RPCE 14.3.3.2), the max_count should be the maximum number of elements including the NUL terminator (i.e., `strlen+1`), and actual_count should also include the NUL terminator. The `ndr_write_string` function uses `strlen(str)` (without +1) for both max_count and actual_count. However, `ndr_write_vstring` correctly uses `strlen+1`. This is an **implementation-level difference** between `ndr_write_string` (no terminator in counts) and `ndr_write_vstring` (includes terminator). The test correctly reflects what the implementation does. Whether the implementation itself is spec-compliant depends on the calling context -- `ndr_write_string` appears to be used for a specific purpose where the terminator is handled differently. Since both the test and implementation agree, and the test is testing the implementation correctly, this is **CORRECT as a test** but the underlying `ndr_write_string` semantics differ from standard NDR varying string semantics.

### BIND PDU p_cont_list Padding

In `build_bind_pdu`, after `num_contexts` (1 byte), 3 bytes of padding are written before the first context. Per MS-RPCE 12.6.4.3, `p_cont_list_t` is:
```
n_context_elem (1 byte)
reserved       (1 byte)  
reserved2      (2 bytes)
p_cont_elem_t[n_context_elem]
```

The code writes:
```c
buf[off++] = 1;    /* num_contexts */
buf[off++] = 0;    /* padding for align4 */
buf[off++] = 0;
buf[off++] = 0;
```

This matches the `reserved` (1 byte) + `reserved2` (2 bytes) = 3 padding bytes. **CORRECT**.

### Context Element Layout

Per MS-RPCE 12.6.4.3, each `p_cont_elem_t` is:
```
p_cont_id        (2 bytes)
n_transfer_syn   (1 byte)
reserved         (1 byte)
abstract_syntax  (20 bytes: UUID=16 + version=4)
transfer_syntaxes[n_transfer_syn] (20 bytes each)
```

The code writes:
```c
*(uint16_t *)(buf + off) = htole16(0); off += 2;  /* context id */
buf[off++] = 1;    /* num_syntaxes */
buf[off++] = 0;    /* padding */
```

**CORRECT** -- matches the reserved byte after n_transfer_syn.

---

## 2. `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_rpc_ndr.c`

| Test | What it tests | Verdict |
|---|---|---|
| `test_ndr_int8_roundtrip` | 8-bit integer write/read | **CORRECT** |
| `test_ndr_int16_roundtrip` | 16-bit integer write/read | **CORRECT** |
| `test_ndr_int32_roundtrip` | 32-bit integer write/read | **CORRECT** |
| `test_ndr_int64_roundtrip` | 64-bit integer write/read | **CORRECT** |
| `test_ndr_bytes_roundtrip` | Raw bytes write/read | **CORRECT** |
| `test_ndr_auto_align_offset_align4` | 4-byte alignment: offset 1 -> 4 | **CORRECT** per MS-RPCE NDR alignment |
| `test_ndr_auto_align_offset_align2` | ALIGN2 flag alone not handled by auto_align_offset | **CORRECT** (documents implementation behavior) |
| `test_ndr_auto_align_offset_align8` | 8-byte alignment: offset 1 -> 8 | **CORRECT** per NDR64 alignment rules |
| `test_ndr_write_string` | Conformant varying string header: max_count(4) + offset(4) + actual_count(4) + UTF-16LE data | **CORRECT** (see note above about strlen vs strlen+1) |
| `test_ndr_offset_advances` | Sequential writes with natural alignment: int8(1) + int16(2-aligned at 2, end=4) + int32(4-aligned at 4, end=8) + int64(8-aligned at 8, end=16) | **CORRECT** per MS-RPCE NDR alignment rules |
| `test_ndr_zero_values` | Zero value round-trip | **CORRECT** |

**NDR Alignment Verification**: The test `test_ndr_offset_advances` verifies that after writing an int8 at offset 0 (new offset=1), writing int16 pads to offset 2 then writes 2 bytes (new offset=4). Per MS-RPCE section 14.2.2, multi-byte scalars must be aligned to their natural boundary. **CORRECT**.

---

## 3. `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_rpc_srvsvc.c`

### Opnum Values

| Operation | Opnum in Code | MS-SRVSVC Spec | Verdict |
|---|---|---|---|
| NetShareEnumAll | 15 | opnum 15 | **CORRECT** |
| NetShareGetInfo | 16 | opnum 16 | **CORRECT** |

### NDR Payload for NetShareEnumAll (opnum 15)

`build_srvsvc_share_enum_all` constructs:
```
server_name:    NULL unique ptr (ref_id=0) -> 4 bytes
level:          int32 (union discriminant, written twice) -> 8 bytes
container ptr:  ref_id=1 -> 4 bytes
container count: 0 -> 4 bytes
container array ptr: 0 (empty) -> 4 bytes
max_size:       0xFFFFFFFF -> 4 bytes
resume_handle:  unique ptr ref_id=1 + value=0 -> 8 bytes
```

Per MS-SRVSVC 3.1.4.8 (NetrShareEnum), the input parameters are:
- ServerName (unique wchar_t*)
- InfoStruct (LPSHARE_ENUM_STRUCT containing Level + union)
- PrefMaxLen
- ResumeHandle (unique DWORD*)

The NDR encoding writes the union discriminant twice (once as the encapsulation tag, once as the union arm selector for non-encapsulated unions). **CORRECT**.

**Note on server_name NULL pointer**: The code uses ref_id=0 to represent a NULL unique pointer. Per NDR rules, a unique pointer with referent_id=0 is a NULL pointer. **CORRECT**.

### NDR Payload for NetShareGetInfo (opnum 16)

`build_srvsvc_share_get_info` constructs:
```
server_name:   NULL unique ptr -> 4 bytes
share_name:    conformant varying string (max_count, offset, actual_count, UTF-16LE)
level:         int32
```

Per MS-SRVSVC 3.1.4.10 (NetrShareGetInfo):
- ServerName (unique wchar_t*)
- NetName (wchar_t* - the share name)
- Level (DWORD)

The share_name is encoded as a conformant-varying string with `max_count = strlen+1`, `offset = 0`, `actual_count = strlen+1` (both include NUL terminator). **CORRECT** per MS-RPCE NDR varying string encoding.

### Test-by-test Review

| Test | Verdict |
|---|---|
| `test_srvsvc_bind` | **CORRECT** |
| `test_srvsvc_share_enum_no_shares` | **CORRECT** -- enum with 0 shares returns valid RESPONSE |
| `test_srvsvc_share_enum_with_shares` | **CORRECT** |
| `test_srvsvc_share_enum_level0` | **CORRECT** -- level 0 is valid (SHARE_INFO_0_CONTAINER) |
| `test_srvsvc_pipe_open_close` | **CORRECT** |
| `test_srvsvc_open_duplicate_handle` | **CORRECT** |
| `test_srvsvc_share_enum_all_level0_with_ipc` | **CORRECT** |
| `test_srvsvc_share_enum_all_level1_with_ipc` | **CORRECT** |
| `test_srvsvc_share_get_info_level0` | **CORRECT** |
| `test_srvsvc_share_get_info_level1` | **CORRECT** |
| `test_srvsvc_share_get_info_nonexistent` | **CORRECT** -- non-existent share still returns RESPONSE PDU (with error status in NDR body) |
| `test_srvsvc_restricted_context` | **CORRECT** |
| `test_srvsvc_alter_context` | **CORRECT** -- ALTER_CONTEXT produces ALTER_CONTEXT_RESP |
| `test_srvsvc_many_shares_enum` | **CORRECT** |
| `test_srvsvc_share_enum_level0_no_shares` | **CORRECT** |
| `test_srvsvc_share_enum_unsupported_level` | **CORRECT** -- level 2 not implemented |
| `test_srvsvc_share_get_info_unsupported_level` | **CORRECT** |
| `test_srvsvc_share_get_info_nonexistent_level0` | **CORRECT** |
| `test_srvsvc_share_with_comment` | **CORRECT** |
| `test_srvsvc_share_get_info_with_comment` | **CORRECT** |
| `test_srvsvc_share_get_info_disk_share_level0` | **CORRECT** |
| `test_srvsvc_share_get_info_disk_share_level1` | **CORRECT** |
| `test_srvsvc_restricted_context_enum_all` | **CORRECT** |
| `test_srvsvc_restricted_context_get_info_level0` | **CORRECT** |
| `test_srvsvc_restricted_context_get_info_level1` | **CORRECT** |
| `test_srvsvc_mixed_share_types_enum` | **CORRECT** |

---

## 4. `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_rpc_wkssvc.c`

### Opnum Values

| Operation | Opnum in Code | MS-WKSS Spec | Verdict |
|---|---|---|---|
| NetWkstaGetInfo | 0 | opnum 0 | **CORRECT** |

### NDR Payload for NetWkstaGetInfo

`build_wkssvc_netwksta_getinfo_str` constructs:
```
server_name:   unique vstring pointer (ref_id=0x00020000 or 0 for NULL)
level:         uint32
```

Per MS-WKSS 3.2.4.1 (NetrWkstaGetInfo):
- ServerName ([in, string, unique] wchar_t*)
- Level ([in] unsigned long)

The `ref_id = 0x00020000` for unique pointers is a conventional non-zero value. **CORRECT**.

### platform_id = 500 check

Test `test_wkssvc_netwksta_getinfo_level100_fields` verifies platform_id = 500 (PLATFORM_ID_NT). Per MS-WKSS 2.2.5.1 (WKSTA_INFO_100), `wki100_platform_id` should be `SV_PLATFORM_ID_NT` = 500. **CORRECT**.

### version_major = 2, version_minor = 1

Test `test_wkssvc_version_fields` verifies version_major=2, version_minor=1. These are implementation-specific values (ksmbd reports itself as Windows version 2.1, which corresponds to a server major/minor version). This is an implementation choice, not a protocol violation. **CORRECT** as a test.

### Test-by-test Review

| Test | Verdict |
|---|---|
| `test_wkssvc_bind` | **CORRECT** |
| `test_wkssvc_bind_ack_fields` | **CORRECT** |
| `test_wkssvc_netwksta_getinfo` | **CORRECT** |
| `test_wkssvc_pipe_close_unknown` | **CORRECT** |
| `test_wkssvc_netwksta_getinfo_level100_fields` | **CORRECT** |
| `test_wkssvc_netwksta_getinfo_invalid_level` | **CORRECT** |
| `test_wkssvc_server_name_in_response` | **CORRECT** |
| `test_wkssvc_domain_name_in_response` | **CORRECT** |
| `test_wkssvc_restricted_context` | **CORRECT** |
| `test_wkssvc_restricted_context_invalid_level` | **CORRECT** |
| `test_wkssvc_null_server_name` | **CORRECT** |
| `test_wkssvc_version_fields` | **CORRECT** |
| `test_wkssvc_ref_pointers` | **CORRECT** |
| `test_wkssvc_response_header_fields` | **CORRECT** |
| `test_wkssvc_sequential_requests` | **CORRECT** |
| `test_wkssvc_custom_workgroup` | **CORRECT** |

---

## 5. `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_rpc_samr.c`

### Opnum Values

| Operation | Opnum in Code | Opnum in Implementation | MS-SAMR Spec | Verdict |
|---|---|---|---|---|
| SamrCloseHandle | 1 | 1 | opnum 1 | **CORRECT** |
| SamrQuerySecurityObject | 3 | 3 | opnum 3 | **CORRECT** |
| SamrLookupDomainInSamServer | 5 | 5 | opnum 5 | **CORRECT** |
| SamrEnumerateDomainsInSamServer | 6 | 6 | opnum 6 | **CORRECT** |
| SamrOpenDomain | 7 | 7 | opnum 7 | **CORRECT** |
| SamrGetAliasMembership | 16 | 16 | opnum 16 | **CORRECT** |
| SamrLookupNamesInDomain | 17 | 17 | opnum 17 | **CORRECT** |
| SamrOpenUser | 34 | 34 | opnum 34 | **CORRECT** |
| SamrQueryInformationUser | 36 | 36 | opnum 36 | **CORRECT** |
| SamrGetGroupsForUser | 39 | 39 | opnum 39 | **CORRECT** |
| SamrConnect5 | 64 | 64 | opnum 64 | **CORRECT** |

### DCE/RPC Request Header Construction

`write_dcerpc_request_header` constructs a standard DCE/RPC REQUEST header followed by the request-specific fields (alloc_hint, context_id, opnum). Per MS-RPCE 12.6.4.9 (`co_request`):
```
alloc_hint  (4 bytes)
p_cont_id   (2 bytes)
opnum       (2 bytes)
```

The code correctly writes alloc_hint=0, context_id=0, opnum=<value>. **CORRECT**.

### WRONG: Call ID Mismatch in Multiple Builders

Several builder functions use **incrementing call_id values** (2, 3, 4, 5, ...) for their request PDUs via `write_dcerpc_request_header`. This is **not a protocol error** -- call_ids are chosen by the client and are arbitrary. The server must echo the call_id in the response. **CORRECT**.

### SamrLookupDomain NDR Encoding

`build_samr_lookup_domain` encodes:
- handle (20 bytes)
- `length` (uint16, name_len * 2) -- byte count of string without NUL
- `size` (uint16, name_len * 2) -- byte count, should be >= length
- ref_id (uint32, 0x00020000)
- max_count (uint32, name_len + 1)
- offset (uint32, 0)
- actual_count (uint32, name_len) -- character count without NUL

Per MS-SAMR 2.2.1.1 (RPC_UNICODE_STRING): `Length` = number of used bytes (excluding NUL), `MaximumLength` >= Length. Then the pointer dereferences to a conformant-varying array where actual_count does NOT include the NUL terminator.

The code has `size = name_len * 2` which equals `length = name_len * 2`. Per spec, `MaximumLength` should be `>= Length`, so it can be equal. The actual_count = name_len (without NUL). **CORRECT**.

### SamrConnect5 NDR Encoding

`build_samr_connect5` encodes:
- server_name: NULL unique ptr (ref_id=0)
- DesiredAccess: 0x000F003F
- InVersion: 1
- InRevisionInfo discriminant: 1
- InRevisionInfo.V1.Revision: 3

Per MS-SAMR 3.1.5.1.3 (SamrConnect5): ServerName is a unique wchar_t*, DesiredAccess is ACCESS_MASK, InVersion is DWORD, InRevisionInfo is a union. The encoding of `{0, 0x000F003F, 1, 1, 3}` is reasonable. **CORRECT**.

### Test-by-test Review

| Test | Verdict |
|---|---|
| `test_samr_bind` | **CORRECT** |
| `test_samr_bind_ack_fields` | **CORRECT** |
| `test_samr_connect5` | **CORRECT** |
| `test_samr_connect5_handle_returned` | **CORRECT** |
| `test_samr_enum_domains` | **CORRECT** |
| `test_samr_enum_domains_bad_handle` | **CORRECT** |
| `test_samr_lookup_domain_builtin` | **CORRECT** |
| `test_samr_lookup_domain_hostname` | **CORRECT** |
| `test_samr_lookup_domain_bad_handle` | **CORRECT** |
| `test_samr_open_domain_success` | **CORRECT** |
| `test_samr_open_domain_bad_handle` | **CORRECT** |
| `test_samr_close_handle` | **CORRECT** |
| `test_samr_close_bad_handle` | **CORRECT** |
| `test_samr_close_with_refcount` | **CORRECT** (implementation-specific refcount behavior) |
| `test_samr_unsupported_opnum` | **CORRECT** |
| `test_samr_full_user_lifecycle` | **CORRECT** -- exercises Connect5 -> OpenDomain -> LookupNames -> OpenUser -> QueryUserInfo -> GetGroupsForUser -> QuerySecurity -> GetAliasMembership -> Close |
| `test_samr_lookup_names_nonexistent` | **CORRECT** |
| `test_samr_lookup_names_bad_handle` | **CORRECT** |
| `test_samr_open_user_wrong_rid` | **CORRECT** |
| `test_samr_open_user_no_lookup` | **CORRECT** |
| `test_samr_open_user_bad_handle` | **CORRECT** |
| `test_samr_query_user_info_bad_handle` | **CORRECT** |
| `test_samr_query_security_bad_handle` | **CORRECT** |
| `test_samr_query_security_no_user` | **CORRECT** |
| `test_samr_get_groups_for_user_bad_handle` | **CORRECT** |

### QUESTIONABLE: SamrOpenDomain Missing SID Parameter

`build_samr_open_domain` constructs:
```
handle (20 bytes)
DesiredAccess (4 bytes, 0x000F003F)
```

Per MS-SAMR 3.1.5.1.5 (SamrOpenDomain), the input is:
```
ServerHandle (20 bytes)
DesiredAccess (4 bytes)
DomainId (SID)
```

The builder **omits the DomainId SID**. The PDU frag_length is set to the end of the buffer (just handle + access mask), which means the DomainId is missing from the wire encoding. This would be malformed per the spec. However, the ksmbd-tools implementation apparently handles this gracefully (returns SUCCESS), meaning the implementation likely does not parse or validate the DomainId field. **QUESTIONABLE** -- the test works against the ksmbd-tools implementation, but the PDU is technically malformed per MS-SAMR. The test is valid as an implementation test, but would fail against a strict MS-SAMR server.

---

## 6. `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_rpc_lsarpc.c`

### Opnum Values

| Operation | Opnum in Code | MS-LSAD Spec | Verdict |
|---|---|---|---|
| LsarClose | 0 | opnum 0 | **CORRECT** |
| LsarQueryInformationPolicy | 7 | opnum 7 | **CORRECT** |
| LsarOpenPolicy2 | 44 | opnum 44 | **CORRECT** |
| LsarLookupSids2 | 57 | opnum 57 | **CORRECT** |
| LsarLookupNames3 | 68 | opnum 68 | **CORRECT** |
| DsRoleGetPrimaryDomainInformation | 0 (dssetup context) | opnum 0 (MS-DSSP) | **CORRECT** |

### LsarOpenPolicy2 (opnum 44)

`build_lsarpc_open_policy2` writes opnum=44 and 64 bytes of zero padding as payload. Per MS-LSAD 3.1.4.4.1 (LsarOpenPolicy2), the input is:
- SystemName (unique wchar_t*)
- ObjectAttributes (LSAPR_OBJECT_ATTRIBUTES)
- DesiredAccess (ACCESS_MASK)

The 64-byte zero payload would encode a NULL SystemName (ref_id=0), a zero-filled ObjectAttributes structure, and DesiredAccess=0. While the ObjectAttributes struct is not fully formed, the implementation likely only checks for basic validity. **CORRECT** as a test (the server accepts it).

### LsarQueryInformationPolicy (opnum 7)

`build_lsarpc_query_info` correctly encodes:
- handle (HANDLE_SIZE bytes)
- level (uint16)

Per MS-LSAD 3.1.4.4.3 (LsarQueryInformationPolicy):
- PolicyHandle (20 bytes)
- InformationClass (uint16, POLICY_INFORMATION_CLASS enum)

**CORRECT**.

### LsarClose (opnum 0)

`build_lsarpc_close` encodes:
- context_id = 0 (lsarpc context)
- opnum = 0
- handle (HANDLE_SIZE bytes)

Per MS-LSAD 3.1.4.4.2 (LsarClose), input is just the ObjectHandle. **CORRECT**.

### DsRoleGetPrimaryDomainInfo (opnum 0 on dssetup context)

`build_dsrole_get_primary_domain_info` encodes:
- context_id = 1 (dssetup context)
- opnum = 0
- level (uint16)

Per MS-DSSP 3.2.5.1 (DsRolerGetPrimaryDomainInformation), input is InfoLevel (DSROLE_PRIMARY_DOMAIN_INFO_LEVEL). **CORRECT**.

### LsarLookupSids2 (opnum 57) NDR Encoding

`build_lsarpc_lookup_sid2` encodes:
- handle (20 bytes)
- num_sids (uint32)
- SID array ref pointer (uint32)
- SID max_count (uint32)
- per-SID ref pointers (uint32 each)
- per-SID data: max_count(uint32) + revision(uint8) + num_subauth(uint8) + authority[6](uint8 each) + sub_auth[](uint32 each)

Per MS-LSAD 2.2.16 (LSAPR_SID_ENUM_BUFFER):
- Entries (ULONG)
- SidInfo (PLSAPR_SID_INFORMATION, conformant array of pointers to SIDs)

The SID encoding follows RPC_SID format: conformant array where max_count = num_subauth, followed by revision, sub_authority_count, IdentifierAuthority[6], SubAuthority[num_subauth]. **CORRECT**.

### LsarLookupNames3 (opnum 68) NDR Encoding

`build_lsarpc_lookup_names3` encodes:
- handle (20 bytes)
- num_names (uint32)
- max_count (uint32) -- conformant array header
- per-name: length(uint16) + size(uint16) + ref_id(uint32) + conformant varying string data

Per MS-LSAD 3.1.4.9 (LsarLookupNames3):
- PolicyHandle (20 bytes)
- Count (ULONG)
- Names (array of RPC_UNICODE_STRING)

Each RPC_UNICODE_STRING: Length(uint16) + MaximumLength(uint16) + Buffer pointer.

The code writes length and size (MaximumLength) correctly: length = namelen*2 (bytes, without NUL), size = (namelen+1)*2 (bytes, with NUL). **CORRECT**.

However, the code writes the ref_id AND the conformant varying string data **inline** for each name in the same loop. Per strict NDR rules, conformant arrays with embedded pointers should have the fixed parts first (length, size, ref_id for all elements), then the deferred pointer data. The ksmbd-tools implementation reads them sequentially, so this works. **QUESTIONABLE** per strict NDR encoding rules but **CORRECT** against the ksmbd-tools implementation.

### Test-by-test Review

| Test | Verdict |
|---|---|
| `test_lsarpc_bind` | **CORRECT** |
| `test_lsarpc_bind_ack_fields` | **CORRECT** |
| `test_lsarpc_dssetup_bind` | **CORRECT** |
| `test_lsarpc_open_policy2` | **CORRECT** |
| `test_lsarpc_open_policy2_handle_nonzero` | **CORRECT** |
| `test_lsarpc_query_info_level5` | **CORRECT** -- level 5 is LSA_POLICY_INFO_ACCOUNT_DOMAIN |
| `test_lsarpc_query_info_invalid_level` | **CORRECT** -- level 3 not implemented |
| `test_lsarpc_query_info_invalid_handle` | **CORRECT** |
| `test_lsarpc_close` | **CORRECT** |
| `test_lsarpc_close_invalid_handle` | **CORRECT** |
| `test_lsarpc_double_close` | **CORRECT** |
| `test_lsarpc_query_after_close` | **CORRECT** |
| `test_lsarpc_lookup_sid2_single` | **CORRECT** |
| `test_lsarpc_lookup_sid2_invalid_handle` | **CORRECT** |
| `test_lsarpc_lookup_names3_*` (multiple tests) | **CORRECT** |
| `test_lsarpc_unsupported_opnum` | **CORRECT** |
| `test_lsarpc_dsrole_*` (multiple tests) | **CORRECT** |

---

## 7. `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_rpc_services.c`

This file tests subsystem lifecycle (init/destroy) and basic management operations (user add/lookup, share hash). No protocol-specific claims.

| Test | Verdict |
|---|---|
| `test_rpc_init_destroy` | **CORRECT** (implementation test) |
| `test_usm_init_destroy` | **CORRECT** (implementation test) |
| `test_shm_init_destroy` | **CORRECT** (implementation test) |
| `test_sm_init_destroy` | **CORRECT** (implementation test) |
| `test_usm_add_lookup_user` | **CORRECT** (implementation test) |
| `test_usm_lookup_nonexistent` | **CORRECT** (implementation test) |
| `test_shm_share_name_hash_consistency` | **CORRECT** (implementation test) |

---

## Summary

### Overall Statistics

- **Total test cases audited**: ~100+ across 7 files
- **CORRECT**: ~97% of test cases
- **WRONG**: 0 findings
- **QUESTIONABLE**: 3 findings

### QUESTIONABLE Findings

1. **`ndr_write_string` max_count/actual_count semantics** (`test_rpc_ndr.c`, `test_ndr_write_string`):
   - The `ndr_write_string` function uses `strlen(str)` (without NUL terminator) for both max_count and actual_count.
   - Per MS-RPCE NDR conformant-varying strings, the counts typically include the NUL terminator.
   - The companion `ndr_write_vstring` function correctly uses `strlen+1`.
   - The test correctly reflects the implementation behavior, so the **test itself is correct**. The underlying implementation function may have been designed for a specific purpose where the NUL is excluded.
   - **Impact**: Low -- `ndr_write_string` is only used internally and the matching read functions expect the same format.

2. **`build_samr_open_domain` missing DomainId SID** (`test_rpc_samr.c`):
   - Per MS-SAMR 3.1.5.1.5, SamrOpenDomain takes `{ServerHandle, DesiredAccess, DomainId}`, but the builder omits the DomainId.
   - The ksmbd-tools implementation handles this gracefully (accepts the request), suggesting it does not validate the DomainId parameter.
   - **Impact**: Low for testing purposes -- the test is valid against ksmbd-tools but would fail against a strictly compliant SAMR server.

3. **LsarLookupNames3 inline pointer data** (`test_rpc_lsarpc.c`):
   - The builder writes pointer referent data inline with the fixed structure parts, rather than deferring pointer data after all fixed array elements.
   - Strict NDR encoding would have all fixed parts `{length, size, ref_id}` for all names first, then all deferred string data.
   - The ksmbd-tools implementation reads them sequentially in a loop and handles this format correctly.
   - **Impact**: Low -- works correctly against ksmbd-tools.

### Protocol Compliance Summary

| Area | Verdict |
|---|---|
| DCE/RPC PDU type constants | All **CORRECT** |
| DCE/RPC PFC flags | All **CORRECT** |
| DCE/RPC header layout (BIND, REQUEST, RESPONSE) | All **CORRECT** |
| NDR Transfer Syntax UUID | **CORRECT** |
| Service Interface UUIDs (SRVSVC, WKSSVC, SAMR, LSARPC, dssetup) | All **CORRECT** |
| Service Interface Versions | All **CORRECT** |
| SRVSVC opcodes (15, 16) | **CORRECT** |
| WKSSVC opcodes (0) | **CORRECT** |
| SAMR opcodes (1, 3, 5, 6, 7, 16, 17, 34, 36, 39, 64) | All **CORRECT** |
| LSARPC opcodes (0, 7, 44, 57, 68) | All **CORRECT** |
| NDR alignment (2, 4, 8 byte) | **CORRECT** |
| NDR conformant varying string encoding | **CORRECT** (vstring includes NUL in counts; string excludes NUL) |
| NDR union encoding (discriminant + arm) | **CORRECT** |
| NDR unique pointer encoding (ref_id=0 for NULL) | **CORRECT** |
| Error handling (bad handles, unsupported opcodes, buffer overflow) | **CORRECT** |