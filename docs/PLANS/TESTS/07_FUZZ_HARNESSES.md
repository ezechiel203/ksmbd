# Test Plan: Fuzz Harnesses

## Current Coverage Summary

Thirteen fuzz harnesses currently exist in `test/fuzz/`. All are implemented as
standalone kernel modules that inline protocol structures and exercise parsing
logic in isolation (no ksmbd module dependency at load time). They self-test on
`module_init` and expose entry points for integration with syzkaller or
libFuzzer-style drivers.

| # | File | What it covers |
|---|------|----------------|
| 1 | `smb2_header_fuzz.c` | SMB2 64-byte header: ProtocolId, StructureSize, Command range, CreditCharge/Request, Flags, NextCommand chain traversal with 8-byte alignment, MessageId, SessionId, TreeId (sync vs async). |
| 2 | `negotiate_context_fuzz.c` | Negotiate context chain: ContextType dispatch (PREAUTH, ENCRYPT, COMPRESS, SIGNING, NETNAME, TRANSPORT, RDMA), DataLength vs remaining buffer, 8-byte-aligned chain walk, expected-count strict mode. |
| 3 | `create_context_fuzz.c` | Create context chain: Next/NameOffset/NameLength/DataOffset/DataLength validation, alignment checks, tag search (DH2Q/DH2C/DHnQ/DHnC/MxAc/QFid/RqLs/AAPL), chain counting, circular reference detection. |
| 4 | `security_descriptor_fuzz.c` | NT security descriptor: osidoffset/gsidoffset/sacloffset/dacloffset, SID revision + num_subauth bounds, ACL size vs num_aces, ACE size chain walk, embedded SID in ACE. |
| 5 | `asn1_fuzz.c` | ASN.1 BER: subid_decode (7-bit continuation), OID decode (first-component split, allocation, cleanup), TLV tag/length parsing (short and long form), hdr_len_bytes computation. |
| 6 | `ndr_fuzz.c` | NDR encode/decode: DOS attribute v3/v4 (string prefix, version match, attr/itime/create_time), NT ACL v4 (hash, description, posix_acl_hash, sd_buf allocation), read_int16/32/64, read_string alignment. |
| 7 | `path_parse_fuzz.c` | Path parsing: filename character validation (control chars, wildcards), backslash/forward-slash conversion, trailing slash removal, stream name parsing (filename:stream:$DATA), wildcard pattern matching (*, ?). |
| 8 | `lock_request_fuzz.c` | SMB2_LOCK: StructureSize=48, LockCount bounds, lock element array, flag validation (shared+exclusive conflict, unlock+lock conflict), byte range overlap detection, offset+length overflow. |
| 9 | `query_set_info_fuzz.c` | SMB2 QUERY_INFO / SET_INFO: InfoType (FILE/FS/SECURITY/QUOTA) and InfoClass range validation, OutputBufferLength cap, InputBufferOffset+Length bounds, BufferOffset+BufferLength bounds. |
| 10 | `quota_request_fuzz.c` | QUERY_QUOTA_INFO: SID list chain traversal (NextEntryOffset), SidLength bounds, SID revision/num_subauth, StartSidOffset/Length, ReturnSingle/RestartScan flags. |
| 11 | `reparse_point_fuzz.c` | Reparse data buffer: ReparseTag dispatch (SYMLINK, MOUNT_POINT, NFS), ReparseDataLength, SubstituteNameOffset/Length + PrintNameOffset/Length within PathBuffer, generic unknown-tag validation. |
| 12 | `dfs_referral_fuzz.c` | DFS_GET_REFERRALS: MaxReferralLevel range (0..4), Unicode RequestFileName null-termination (16-bit scan), backslash prefix check. |
| 13 | `transform_header_fuzz.c` | SMB3 transform header: ProtocolId (0xFD 'S' 'M' 'B'), OriginalMessageSize (zero, cap, exceeds buffer), Flags (ENCRYPTED bit), SessionId non-zero, all-zero Signature/Nonce warnings. |


## Gap Analysis

Every byte that crosses a trust boundary (network wire, netlink, xattr) must be
fuzz-tested. The following input parsing surfaces have **no** dedicated fuzz
harness:

### Critical (remote unauthenticated attacker)

| Surface | Source file(s) | Risk |
|---------|---------------|------|
| **SMB1 PDU parsing** | `smb1pdu.c`, `smb1misc.c` | Full SMB1 command dispatch: NEGOTIATE, SESSION_SETUP_ANDX, TREE_CONNECT_ANDX, TRANSACTION, TRANSACTION2, NT_TRANSACT, NT_CREATE_ANDX, READ_ANDX, WRITE_ANDX, LOCKING_ANDX, etc. The `ksmbd_smb1_check_message()` validation plus per-command handlers process dozens of variable-length fields. |
| **Session setup (NTLMSSP/SPNEGO)** | `auth.c`, `smb2_session.c`, `ksmbd_spnego_negtokeninit.asn1.c`, `ksmbd_spnego_negtokentarg.asn1.c` | `ksmbd_decode_ntlmssp_neg_blob()`, `ksmbd_decode_ntlmssp_auth_blob()`: extract DomainName, UserName, Workstation, NtChallengeResponse, LmChallengeResponse from offsets inside authenticate_message. SPNEGO wrapping adds another layer of ASN.1 TLV. Pre-auth, unauthenticated. |
| **Compression (LZNT1, LZ77, LZ77+Huffman)** | `smb2_compress.c` | `ksmbd_lznt1_decompress()`: chunk-header parsing, back-reference token extraction with variable-width offset/length fields; `ksmbd_lz77_decompress()`: flag-byte + literal/match decoding; `lz77h_decompress()`: 256-byte Huffman table build + canonical decode + LZ77 match expansion. Decompression bombs (small input -> huge output) and out-of-bounds writes in output buffer. |
| **QUIC Initial packet parsing** | `transport_quic.c` | `quic_parse_initial_packet()`: first-byte form/type bits, Version, DCID/SCID length+data, varint token length, varint payload length, packet number. `ksmbd_quic_get_varint()`: variable-length integer decode. QUIC AEAD decrypt path. Unauthenticated, first bytes received on UDP. |
| **Compound request chaining** | `smb2_pdu_common.c` | `init_chained_smb2_rsp()`, compound FID propagation from CREATE/FLUSH/READ/WRITE/CLOSE etc. NextCommand offset validation, related/unrelated flag handling, SessionId/TreeId inheritance. Malformed chains can confuse FID state. |
| **SMB2 IOCTL FSCTL input buffers** | `ksmbd_fsctl.c`, `ksmbd_fsctl_extra.c` | FSCTL_COPYCHUNK: `copychunk_ioctl_req` with ChunkCount array of `srv_copychunk`; FSCTL_VALIDATE_NEGOTIATE_INFO: dialects array; FSCTL_PIPE_TRANSCEIVE: raw pipe data; FSCTL_SET_COMPRESSION: USHORT; FSCTL_DUPLICATE_EXTENTS_TO_FILE(_EX): offset/length struct; FSCTL_QUERY_FILE_REGIONS: input region struct; FSCTL_OFFLOAD_READ/WRITE: token buffers; FSCTL_MARK_HANDLE; FSCTL_PIPE_WAIT: NameLength + pipe name; FSCTL_FILE_LEVEL_TRIM: trim ranges. Each FSCTL has its own input format. |
| **EA (Extended Attribute) buffers** | `smb2_create.c`, `smb2_query_set.c` | `smb2_set_ea()`: walks chained `smb2_ea_info` entries using NextEntryOffset, EaNameLength, EaValueLength. SET_INFO with FILE_FULL_EA_INFORMATION. |
| **Tree connect share name** | `smb2_tree.c`, `smb1pdu.c` | UTF-16LE share path extraction via `smb_strndup_from_utf16()`, `ksmbd_extract_sharename()`, TREE_CONNECT_Request_Extension parsing when EXTENSION_PRESENT flag set, PathOffset relative to extension base. |
| **Unicode/UTF-16 conversion** | `unicode.c` | `smb_strndup_from_utf16()`, `smb_utf16_bytes()`: called on every UTF-16LE string from the wire. Surrogate pair handling, null-termination, odd-length buffers, code page conversion. |

### High (authenticated attacker or secondary parsing)

| Surface | Source file(s) | Risk |
|---------|---------------|------|
| **RSVD tunnel operations** | `ksmbd_rsvd.c` | SVHDX tunnel header validation, SCSI operation passthrough, per-opcode subcommand dispatch. Input is from authenticated IOCTL but format is complex (nested headers, SCSI CDB). |
| **IPC/Netlink messages** | `transport_ipc.c` | `ksmbd_nl_policy[]`, `ksmbd_ipc_login_request()`, `ksmbd_ipc_spnego_authen_request()`, `ksmbd_ipc_tree_connect_request()`: kernel parses responses from userspace daemon via genetlink. A compromised or buggy daemon could send malformed payloads. |
| **Filename/path validation** | `misc.c`, `smb2_create.c` | Path traversal (../../), DFS path prefix stripping, stream name splitting, case conversion. Already partially covered by `path_parse_fuzz.c` but does not test the actual `ksmbd_validate_filename()` from misc.c which has additional logic (path component checks). |
| **Directory enumeration patterns** | `smb2_dir.c` | `ksmbd_vfs_lookup_wildcard()`, DOS wildcard translation (? -> >, * -> <), RESTART_SCANS/REOPEN handling, dot_dotdot reset. |
| **Oplock/lease break requests** | `oplock.c` | Lease key parsing from create context, oplock break acknowledgment parsing. |
| **BranchCache SRV_READ_HASH** | `ksmbd_branchcache.c` | Input validation of hash request parameters, Content Information V1 generation. |
| **APP_INSTANCE_ID / VERSION** | `ksmbd_app_instance.c` | Create context parsing for 16-byte GUID + version high/low. |
| **Witness registration** | `ksmbd_witness.c` | Resource name parsing, registration ID validation. |

### Medium (less likely attack path, but still trust-boundary)

| Surface | Source file(s) | Risk |
|---------|---------------|------|
| **SMB2 negotiate request body** | `smb2_negotiate.c` | Dialect array, SecurityBuffer, ClientGuid, NegotiateContextOffset/Count, per-dialect negotiate context decode (Preauth HashId count, Encryption cipher count, Compression algorithm count, Signing algorithm count, RDMA transform count). |
| **VSS (Volume Shadow Copy)** | `ksmbd_vss.c` | Snapshot timestamp parsing in create context. |
| **Resilient handle** | `ksmbd_resilient.c` | Resilient open context parsing. |
| **Notify change request** | `smb2_notify.c`, `ksmbd_notify.c` | CompletionFilter, WATCH_TREE flag, OutputBufferLength. |
| **SMB2 READ/WRITE request** | `smb2_read_write.c` | DataOffset validation, Offset overflow (0xFFFFFFFFFFFFFFFF sentinel), ReadChannelInfo/WriteChannelInfo for RDMA. |
| **SMB3 compression header** | `smb2_compress.c` | SMB2_COMPRESSION_TRANSFORM_HEADER: ProtocolId (0xFC 'S' 'M' 'B'), OriginalCompressedSegmentSize, CompressionAlgorithm, chained vs unchained flag, Offset field. |


## New Fuzz Harnesses Required

### 1. smb1_pdu_fuzz.c (NEW) -- CRITICAL

**What to fuzz:**
- SMB1 header (32 bytes): Protocol (0xFF 'S' 'M' 'B'), Command byte, Status, Flags/Flags2, PIDHigh, SecurityFeatures, TID, PIDLow, UID, MID
- Per-command request structures: WordCount + ParameterWords + ByteCount + Bytes
- `ksmbd_smb1_check_message()`: validates WordCount vs expected, ByteCount vs remaining buffer
- AndX chain traversal: AndXCommand, AndXOffset validation
- TRANSACTION/TRANSACTION2/NT_TRANSACT: ParameterOffset, ParameterCount, DataOffset, DataCount (secondary fragments too)
- SMB1 NEGOTIATE: dialect string list parsing (NUL-separated, "\2" prefix)
- SMB1 SESSION_SETUP_ANDX: CaseInsensitivePassword, CaseSensitivePassword, AccountName, PrimaryDomain extraction

**Entry points:**
- `fuzz_smb1_header()`: header validation
- `fuzz_smb1_check_message()`: full message validation against command table
- `fuzz_smb1_andx_chain()`: AndX chain traversal
- `fuzz_smb1_negotiate_dialects()`: dialect string parsing
- `fuzz_smb1_transaction()`: TRANSACTION parameter/data offset validation

**Mutation strategy:**
- Seed with valid SMB1 packets captured from smbclient
- Mutate WordCount (0..255), ByteCount (0..65535), AndXOffset (pointing backward, beyond buffer, into header)
- Craft TRANSACTION requests with overlapping Parameter/Data regions
- Empty dialect lists, single-byte dialects, unterminated strings

---

### 2. session_setup_fuzz.c (NEW) -- CRITICAL

**What to fuzz:**
- NTLMSSP NEGOTIATE_MESSAGE: Signature ("NTLMSSP\0"), MessageType, NegotiateFlags, DomainNameFields (Len/MaxLen/Offset), WorkstationFields
- NTLMSSP AUTHENTICATE_MESSAGE: LmChallengeResponseFields, NtChallengeResponseFields, DomainNameFields, UserNameFields, WorkstationFields, EncryptedRandomSessionKeyFields, NegotiateFlags, MIC
- `ksmbd_decode_ntlmssp_neg_blob()`: validates minimum size, extracts flags
- `ksmbd_decode_ntlmssp_auth_blob()`: extracts all offset/length pairs, calls `smb_strndup_from_utf16()` on each, computes MIC
- NTLMSSP_ANONYMOUS detection (zero-length NtChallengeResponse)
- SPNEGO NegTokenInit / NegTokenTarg ASN.1 wrapping: outer SEQUENCE, mechTypes OID list, mechToken containing NTLMSSP blob, mechListMIC

**Entry points:**
- `fuzz_ntlmssp_negotiate()`: raw NEGOTIATE_MESSAGE blob
- `fuzz_ntlmssp_authenticate()`: raw AUTHENTICATE_MESSAGE blob
- `fuzz_spnego_negtokeninit()`: full SPNEGO NegTokenInit wrapping NTLMSSP
- `fuzz_spnego_negtokentarg()`: full SPNEGO NegTokenTarg wrapping NTLMSSP

**Mutation strategy:**
- Offset fields pointing before Signature, after buffer end, overlapping each other
- Len=0 with non-zero Offset and vice versa
- MaxLen < Len
- DomainName/UserName/Workstation with embedded NULs, odd lengths (UTF-16 alignment)
- NtChallengeResponse with lengths 0, 1, 24 (NTLMv1), huge (65535)
- SPNEGO with truncated OID, wrong mechType, missing mechToken, extra trailing data

---

### 3. compression_fuzz.c (NEW) -- CRITICAL

**What to fuzz:**
- **LZNT1** (`ksmbd_lznt1_decompress()`): 2-byte chunk headers (signature bit, compressed-size), flag bytes, back-reference tokens with variable-width offset/length bit splitting, uncompressed chunk passthrough
- **LZ77 plain** (`ksmbd_lz77_decompress()`): flag bytes (8 bits -> 8 literal-or-match decisions), match offset/length pairs, end-of-stream detection
- **LZ77+Huffman** (`lz77h_decompress()`): 256-byte Huffman table (512 4-bit code lengths packed), canonical Huffman tree build, bitstream decode, LZ77 match token expansion (symbols 256-511)
- **Compression header** (`smb3_decompress_header()`): ProtocolId 0xFC 'S' 'M' 'B', OriginalCompressedSegmentSize, CompressionAlgorithm, chained/unchained, Offset

**Entry points:**
- `fuzz_lznt1_decompress()`: raw LZNT1 stream
- `fuzz_lz77_decompress()`: raw LZ77 plain stream
- `fuzz_lz77h_decompress()`: raw LZ77+Huffman stream (256-byte table + bitstream)
- `fuzz_compression_header()`: SMB3 compression transform header

**Mutation strategy:**
- **Decompression bombs**: 1 chunk header claiming 4096 bytes of output, all back-references to offset=1 (run-length expansion)
- **Huffman table corruption**: all code lengths = 15, all = 0, single valid symbol
- **LZ77 match pointing before start of output**: offset > current position
- **LZNT1 chunk size mismatches**: chunk header says 100 bytes but stream has 10
- **Output buffer exactly at capacity**: OriginalCompressedSegmentSize = output_len, then one more byte
- **Zero-length input**, single-byte input, max-size input (16MB)

---

### 4. quic_packet_fuzz.c (NEW) -- CRITICAL

**What to fuzz:**
- `quic_parse_initial_packet()`: first-byte (Form, Fixed, Type bits), Version (4 bytes), DCID length + data, SCID length + data, token varint length + data, payload varint length
- `ksmbd_quic_get_varint()`: 1/2/4/8 byte variable-length integer encoding
- `ksmbd_quic_put_varint()`: encoding round-trip
- Header protection removal: `ksmbd_quic_apply_header_protection()` sample/mask logic
- AEAD decrypt of Initial packet payload
- QUIC CRYPTO frame extraction from decrypted payload

**Entry points:**
- `fuzz_quic_varint()`: raw bytes -> varint decode
- `fuzz_quic_initial_parse()`: full Initial packet header parsing
- `fuzz_quic_header_protection()`: packet number unmasking with crafted sample bytes

**Mutation strategy:**
- Version fields: 0x00000000 (version negotiation), 0xFFFFFFFF, valid (0x00000001)
- DCID/SCID lengths: 0, 1, 20 (max), 21 (over max), 255
- Token length varint: 0, huge value, varint encoding with wrong prefix bits
- Truncated packets at every possible offset (1..N)
- Valid Initial with corrupted AEAD tag (1-bit flip)

---

### 5. ipc_netlink_fuzz.c (NEW) -- HIGH

**What to fuzz:**
- `ksmbd_nl_policy[]`: attribute validation for each genetlink command
- Login response parsing: `struct ksmbd_login_response` fields
- Share config response parsing: `struct ksmbd_share_config_response`
- SPNEGO authentication response parsing
- Tree connect response parsing
- Witness notification payloads
- QUIC handshake response parsing

**Entry points:**
- `fuzz_ipc_login_response()`: raw response buffer
- `fuzz_ipc_share_config_response()`: raw share config
- `fuzz_ipc_spnego_response()`: raw SPNEGO auth response
- `fuzz_ipc_quic_handshake_response()`: raw QUIC HS response

**Mutation strategy:**
- Response with zero-length payload, truncated struct, huge vhost_name
- Version field mismatch
- Share flags with all bits set
- SPNEGO response with oversized blob_len

---

### 6. ea_buffer_fuzz.c (NEW) -- HIGH

**What to fuzz:**
- `smb2_set_ea()`: chained `smb2_ea_info` entries (NextEntryOffset, Flags, EaNameLength, EaValueLength, name[], value[])
- `smb2_get_ea()`: `smb2_ea_info_req` input buffer (NextEntryOffset, EaNameLength, EaName)
- EA in CREATE context: `create_ea_buf_req` -> embedded `smb2_ea_info`
- FILE_FULL_EA_INFORMATION in SET_INFO

**Entry points:**
- `fuzz_ea_set()`: raw EA buffer as would appear in SET_INFO
- `fuzz_ea_create_context()`: EA buffer wrapped in create context
- `fuzz_ea_query()`: EA query info request buffer

**Mutation strategy:**
- NextEntryOffset: 0 (last), pointing backward, not aligned, past end
- EaNameLength: 0, 255, exceeds remaining buffer
- EaValueLength: 0, 0xFFFF, exceeds remaining buffer
- EaName not NUL-terminated
- Chain of 1000+ entries (allocation exhaustion)
- Single entry with NextEntryOffset != 0 but no following data

---

### 7. copychunk_fuzz.c (NEW) -- HIGH

**What to fuzz:**
- `copychunk_ioctl_req`: SourceKey (24 bytes), ChunkCount, Reserved, `srv_copychunk[]` array
- Each `srv_copychunk`: SourceOffset, TargetOffset, Length
- Chunk count vs input buffer length validation
- `ksmbd_server_side_copy_max_chunk_count()` limit
- Overlapping source/target ranges

**Entry points:**
- `fuzz_copychunk_request()`: raw FSCTL_COPYCHUNK input buffer

**Mutation strategy:**
- ChunkCount: 0, 1, max, max+1, 0xFFFFFFFF
- Input buffer exactly `sizeof(copychunk_ioctl_req)` (no chunks), with ChunkCount > 0
- Chunk with Length = 0, Length = 0xFFFFFFFF
- SourceOffset + Length overflow
- 256+ chunks (exceeds max_chunk_count)

---

### 8. rsvd_tunnel_fuzz.c (NEW) -- HIGH

**What to fuzz:**
- `svhdx_tunnel_operation_header`: OperationCode prefix validation (0x02xxxxxx), RequestId, Status
- Per-opcode dispatch: GET_INITIAL_INFO, SCSI_OPERATION, CHECK_CONNECTION_STATUS, SRB_STATUS, GET_DISK_INFO, VALIDATE_DISK, META_OPERATION_START, VHDSET_QUERY, etc.
- SCSI CDB passthrough: CDB length, data transfer length, sense data length
- Version 1 vs Version 2 opcode validation

**Entry points:**
- `fuzz_rsvd_tunnel_header()`: tunnel header validation
- `fuzz_rsvd_scsi_operation()`: SCSI operation input parsing

**Mutation strategy:**
- OperationCode with wrong prefix byte, valid prefix + invalid sub-code
- Input buffer shorter than tunnel header
- SCSI CDB with oversized DataTransferLength
- RequestId boundary values (0, UINT_MAX)

---

### 9. validate_negotiate_fuzz.c (NEW) -- HIGH

**What to fuzz:**
- `fsctl_validate_negotiate_info_handler()`: `struct validate_negotiate_info_req` containing Capabilities, Guid, SecurityMode, DialectCount, Dialects[] array
- DialectCount vs buffer length
- Dialect values: valid (0x0202, 0x0210, etc.), invalid (0xFFFF, 0x0000)
- Comparison against negotiated values (Guid, SecurityMode mismatch -> disconnect)

**Entry points:**
- `fuzz_validate_negotiate_info()`: raw FSCTL input buffer

**Mutation strategy:**
- DialectCount: 0, 1, 64, 0xFFFF
- Buffer with DialectCount=100 but only 4 bytes of dialect data
- All dialects set to 0x02FF (wildcard)
- Capabilities with all bits set

---

### 10. share_name_fuzz.c (NEW) -- MEDIUM

**What to fuzz:**
- `smb_strndup_from_utf16()`: UTF-16LE tree path -> UTF-8 conversion
- `ksmbd_extract_sharename()`: splits `\\server\share` or `\\server\share\extra`
- Share name length validation (>= 80 chars -> STATUS_BAD_NETWORK_NAME)
- TREE_CONNECT_Request_Extension: PathOffset relative to extension base when EXTENSION_PRESENT flag set

**Entry points:**
- `fuzz_extract_sharename()`: raw UTF-16LE path bytes
- `fuzz_tree_connect_extension()`: TREE_CONNECT request with extension

**Mutation strategy:**
- Path with no backslashes, all backslashes, UNC with embedded NULs
- Odd-length byte arrays (breaks UTF-16 alignment)
- Share name exactly 79, 80, 81 characters
- Extension present flag with PathOffset = 0, PathOffset past end

---

### 11. filename_fuzz.c (NEW) -- MEDIUM

**What to fuzz:**
- `smb_strndup_from_utf16()` for CREATE NameLength/Buffer
- `ksmbd_validate_filename()` from misc.c: per-character validation, control chars, reserved names (CON, PRN, AUX, NUL, COM1..9, LPT1..9)
- Path traversal: `../`, `..\\`, `....//`, `..%5c`, case variations
- NameLength validation: must be even (UTF-16LE), odd -> EINVAL
- Stream name extraction: `:stream:$DATA`, `:stream:$INDEX_ALLOCATION`
- Long paths (> PATH_MAX), deeply nested paths

**Entry points:**
- `fuzz_create_filename()`: raw UTF-16LE name as in CREATE request
- `fuzz_path_traversal()`: attempt to escape share root

**Mutation strategy:**
- NUL bytes embedded at various positions in UTF-16LE name
- Surrogate pairs (high surrogate without low, orphaned low surrogate)
- Windows reserved device names followed by `.txt`, space, colon
- Path components of length 255, 256, 257 (NTFS limit testing)
- Mix of forward slashes and backslashes

---

### 12. wildcard_fuzz.c (NEW) -- MEDIUM

**What to fuzz:**
- `match_pattern()` from misc.c: `*` and `?` matching, case-insensitive
- DOS wildcard translation: `?` -> `>` (matches any single char or nothing at end), `*` -> `<` (matches to dot), `"` -> `.` (matches dot or end)
- QUERY_DIRECTORY FileNamePattern: `*`, `*.txt`, `???.*`, `<.doc`
- Pattern matching termination guarantees (no exponential blowup)

**Entry points:**
- `fuzz_match_pattern()`: (string, pattern) pair
- `fuzz_dos_wildcard()`: DOS-translated wildcard matching

**Mutation strategy:**
- Pattern: 100+ consecutive `*` characters (exponential blowup test)
- Pattern: alternating `*?*?*?` with long string
- Pattern and string both > 1024 characters
- Empty pattern, empty string, both empty
- Pattern with only DOS wildcards (`<`, `>`, `"`)

---

### 13. compound_request_fuzz.c (NEW) -- CRITICAL

**What to fuzz:**
- SMB2 compound request chaining: NextCommand offset in each header
- Related (SMB2_FLAGS_RELATED_OPERATIONS) vs unrelated compounds
- `init_chained_smb2_rsp()`: FID propagation from CREATE to subsequent commands
- SessionId/TreeId inheritance in related compounds
- Error propagation: compound_err_status cascading
- Compound of N requests where request N has NextCommand pointing back to request 1 (circular)

**Entry points:**
- `fuzz_compound_chain()`: buffer containing 2-8 chained SMB2 requests with headers + minimal bodies
- `fuzz_compound_fid_propagation()`: CREATE + (READ|WRITE|CLOSE) sequence

**Mutation strategy:**
- NextCommand: 0 (last), 64 (minimum), 63 (unaligned), pointing past buffer, pointing into middle of previous header
- Related flag on first request (should be cleared)
- Unrelated flag on subsequent request in related chain
- Mix of valid and invalid commands in chain
- Chain of 256 requests (stress compound processing limit)

---

### 14. tree_connect_fuzz.c (NEW) -- MEDIUM

**What to fuzz:**
- `smb2_tree_connect()`: StructureSize, PathOffset, PathLength, share path extraction
- Flag validation: CLUSTER_RECONNECT, REDIRECT_TO_OWNER, EXTENSION_PRESENT
- Extension parsing: PathOffset relative to Buffer[0] when EXTENSION_PRESENT
- Share type validation (DISK, PIPE, PRINT)
- `ksmbd_extract_sharename()` on extracted path

**Entry points:**
- `fuzz_tree_connect_request()`: raw SMB2 TREE_CONNECT request body

**Mutation strategy:**
- PathOffset: 0, pointing before Buffer, pointing past end
- PathLength: 0, odd (UTF-16 misalignment), > buffer
- EXTENSION_PRESENT with zero-length extension
- Share path with no backslash separator, IPC$ pipe path, deeply nested path

---

### 15. negotiate_request_fuzz.c (NEW) -- HIGH

**What to fuzz:**
- SMB2 NEGOTIATE request body: StructureSize (36), DialectCount, SecurityMode, Capabilities, ClientGuid, NegotiateContextOffset, NegotiateContextCount
- Dialect array: count vs buffer length, valid/invalid dialect values, duplicate dialects
- Negotiate context chain: already partially covered by `negotiate_context_fuzz.c` but not in the context of a full NEGOTIATE request (offsets relative to header start)
- Preauth integrity context: HashAlgorithmCount=0 (now rejected), HashId values
- Encryption context: CipherCount=0, supported/unsupported cipher IDs
- Compression context: CompressionAlgorithmCount=0, algorithm list
- Signing context: SigningAlgorithmCount=0 (now rejected), algorithm values
- Duplicate context type detection

**Entry points:**
- `fuzz_negotiate_request()`: full NEGOTIATE request body including dialect array and negotiate contexts

**Mutation strategy:**
- DialectCount: 0, 1, 64, 0xFFFF
- NegotiateContextOffset: pointing before end of dialects, past end of buffer
- NegotiateContextCount: mismatch with actual contexts in buffer
- Mix of SMB 2.0.2 and 3.1.1 dialects (triggers different code paths)
- SecurityMode with reserved bits set

---

### 16. unicode_conversion_fuzz.c (NEW) -- MEDIUM

**What to fuzz:**
- `smb_strndup_from_utf16()`: the central UTF-16LE to UTF-8 conversion used everywhere
- `smb_utf16_bytes()`: length computation
- `smb_strtoUTF16()`: UTF-8 to UTF-16LE (used in responses, but round-trip matters)
- Surrogate pair handling, BOM handling, odd-length source buffers
- Code page conversion for non-Unicode paths (SMB1 legacy)

**Entry points:**
- `fuzz_utf16_to_utf8()`: raw UTF-16LE bytes -> conversion
- `fuzz_utf8_to_utf16()`: raw UTF-8 bytes -> conversion
- `fuzz_utf16_roundtrip()`: encode then decode, verify equality

**Mutation strategy:**
- Lone high surrogates (0xD800-0xDBFF without following low)
- Lone low surrogates (0xDC00-0xDFFF without preceding high)
- Overlong sequences in the UTF-8 direction
- 0xFFFE/0xFFFF (noncharacters), 0xFEFF (BOM)
- Odd-length buffer (last byte is first byte of an incomplete code unit)
- Very long strings (PATH_MAX, 2*PATH_MAX)

---

### 17. smb3_compression_header_fuzz.c (NEW) -- MEDIUM

**What to fuzz:**
- SMB3 compression transform header (separate from the data decompression covered by compression_fuzz.c)
- ProtocolId: 0xFC 'S' 'M' 'B'
- OriginalCompressedSegmentSize
- CompressionAlgorithm (LZNT1=1, LZ77=2, LZ77+Huffman=3, PATTERN_V1=4)
- Flags: SMB2_COMPRESSION_FLAG_CHAINED vs unchained
- Chained compression header: Offset field, multiple chained segments
- Relationship between OriginalCompressedSegmentSize and actual decompressed data

**Entry points:**
- `fuzz_compression_transform_header()`: raw compression header
- `fuzz_chained_compression()`: multiple chained compression headers

**Mutation strategy:**
- Algorithm value: 0 (none), 1-4 (valid), 5+ (invalid)
- Chained flag with Offset = 0
- OriginalCompressedSegmentSize: 0, 1, 0xFFFFFFFF
- Chained segments with total exceeding max transaction size

---

### 18. pipe_transceive_fuzz.c (NEW) -- MEDIUM

**What to fuzz:**
- `fsctl_pipe_transceive_handler()`: raw data sent to named pipe (IPC$)
- DCE/RPC PDU parsing on the pipe: rpc_request_hdr, rpc_bind_hdr
- Opnum dispatch, fragmentation (PFC_FIRST_FRAG, PFC_LAST_FRAG)
- `FSCTL_PIPE_WAIT`: `fsctl_pipe_wait_request` struct (TimeoutSpecified, NameLength, Name)
- `FSCTL_PIPE_PEEK`: output buffer validation

**Entry points:**
- `fuzz_pipe_transceive()`: raw pipe data
- `fuzz_pipe_wait()`: FSCTL_PIPE_WAIT input buffer

**Mutation strategy:**
- DCE/RPC header with wrong version, fragmented with missing last fragment
- PIPE_WAIT with NameLength > remaining buffer, NameLength = 0
- TimeoutSpecified = TRUE with Timeout = 0, MAXUINT64
- Pipe name with path separators, NUL bytes

---

### 19. oplock_lease_fuzz.c (NEW) -- MEDIUM

**What to fuzz:**
- Lease create context (RqLs tag): LeaseKey (16 bytes), LeaseState, LeaseFlags, LeaseDuration, ParentLeaseKey
- Oplock break acknowledgment: StructureSize, OplockLevel, FileId
- `smb2_find_context_vals()` for lease context extraction
- Lease version 1 vs version 2 (v2 has ParentLeaseKey, Epoch)

**Entry points:**
- `fuzz_lease_create_context()`: raw RqLs create context data
- `fuzz_oplock_break_ack()`: raw oplock break ack request body

**Mutation strategy:**
- LeaseState: all bits set (READ|HANDLE|WRITE + reserved), 0
- LeaseFlags: BREAK_IN_PROGRESS with no active lease
- OplockLevel: invalid values (3, 4, 255)
- DataLength in create context too small for lease structure

---

### 20. app_instance_fuzz.c (NEW) -- LOW

**What to fuzz:**
- APP_INSTANCE_ID create context: StructureSize (20), 4-byte padding, 16-byte GUID
- APP_INSTANCE_VERSION create context: StructureSize (24), Reserved, AppInstanceVersionHigh, AppInstanceVersionLow
- Context data too short for declared structure size
- Duplicate APP_INSTANCE_ID contexts in same CREATE

**Entry points:**
- `fuzz_app_instance_id()`: raw context data
- `fuzz_app_instance_version()`: raw context data

**Mutation strategy:**
- StructureSize: 0, 19, 20, 21, 0xFFFF
- GUID: all zeros, all ones, random
- Version values: 0/0, MAX/MAX, HIGH > LOW


## Improvements to Existing Harnesses

### 1. smb2_header_fuzz.c

**Missing mutations:**
- Does not test SMB2_FLAGS_SIGNED (bit 3) interaction with Signature field
- Does not test SMB2_FLAGS_ASYNC_COMMAND with AsyncId extraction vs SyncHdr
- Does not test CreditCharge interaction with multi-credit commands
- NextCommand chain does not test circular references (offset points back to start)
- Does not test SMB2_FLAGS_RELATED_OPERATIONS (compound related requests)
- No ChannelSequence field extraction (from Status field in low 16 bits for request)

**Recommended additions:**
- Add `fuzz_smb2_header_flags()` that exercises flag-dependent field interpretation
- Add `fuzz_smb2_header_circular_chain()` with a NextCommand pointing to offset 0
- Add credit charge validation (CreditCharge * 65536 vs payload size)
- Test with exactly 64 bytes (minimum), 65 bytes, 63 bytes (too short)

### 2. negotiate_context_fuzz.c

**Missing mutations:**
- Does not test duplicate ContextTypes (ksmbd now rejects with STATUS_INVALID_PARAMETER)
- Does not test inner structure of each context type (e.g., HashAlgorithmCount inside PREAUTH_INTEGRITY)
- Does not test NETNAME_NEGOTIATE_CONTEXT_ID with oversized or zero-length NetName
- Does not test TRANSPORT_CAPABILITIES or RDMA_TRANSFORM_CAPABILITIES content
- Missing test for context at exact end of buffer (0 bytes remaining after last context)

**Recommended additions:**
- Add per-context-type inner validation functions (PREAUTH: HashAlgorithmCount, SaltLength, Salt data; ENCRYPT: CipherCount, Ciphers; etc.)
- Add duplicate detection test (two PREAUTH contexts in chain)
- Add edge case: single context fills entire buffer exactly

### 3. create_context_fuzz.c

**Missing mutations:**
- Does not test tag lengths other than 4 (e.g., SMB2_CREATE_APP_INSTANCE_ID is a 16-byte binary tag)
- Does not test DataLength = 0 (empty create context data area)
- Does not test overlap between NameOffset..NameLength and DataOffset..DataLength regions
- Chain with Next pointing exactly to end of buffer (zero-size final entry)
- Missing POSIX create context tag testing

**Recommended additions:**
- Add binary tag search (not just 4-byte ASCII tags)
- Add overlap detection between name and data regions
- Add test with 100+ chained contexts (stress test)

### 4. security_descriptor_fuzz.c

**Missing mutations:**
- Does not test Self-Relative flag in type field (affects offset interpretation)
- Does not test overlapping SID regions (osidoffset and gsidoffset pointing to same location)
- Does not test DACL with zero ACEs but non-zero ACL size
- Does not test ACE type field values (ACCESS_ALLOWED=0, ACCESS_DENIED=1, SYSTEM_AUDIT=2, etc.)
- Missing SACL-specific validation (SYSTEM_AUDIT_ACE, SYSTEM_MANDATORY_LABEL_ACE)
- Does not test osidoffset/gsidoffset/sacloffset/dacloffset all pointing to same byte
- ACE with size field = 0 (infinite loop potential)

**Recommended additions:**
- Add `fuzz_overlapping_sids()` with all offsets pointing to same location
- Add ACE type validation
- Add test with ACE size = 0 (minimum: sizeof(smb_ace))
- Add test with ACL revision field validation (must be 2 or 4)

### 5. asn1_fuzz.c

**Missing mutations:**
- Does not test indefinite-length encoding (0x80 length byte)
- Does not test constructed vs primitive tag distinction
- Does not test multi-byte tags (tag number >= 31 uses continuation bytes)
- Does not exercise the actual SPNEGO NegTokenInit/NegTokenTarg ASN.1 parsers from `ksmbd_spnego_negtokeninit.asn1.c`
- subid_decode: does not test integer overflow (64+ continuation bytes -> shift beyond unsigned long)
- OID decode: does not test vlen=0 edge case after the +1 adjustment

**Recommended additions:**
- Add `fuzz_asn1_indefinite_length()` with 0x80 length byte
- Add subid_decode with 20+ continuation bytes (overflow test)
- Add constructed SEQUENCE containing nested SEQUENCEs (depth limit test)

### 6. ndr_fuzz.c

**Missing mutations:**
- Does not test read_string with very long unterminated strings (strnlen exhaustion)
- Does not test ALIGN() in read_string causing offset to jump past length
- Does not test ndr_encode functions (encode then decode round-trip)
- Version field values other than 3 and 4 (e.g., 0, 1, 2, 5, 65535)
- Missing ndr_decode_v3_ntacl() testing

**Recommended additions:**
- Add version brute-force: all u16 values
- Add string with NUL at position 0 (empty string), NUL at max, no NUL at all
- Add encode-decode round-trip fuzzing

### 7. path_parse_fuzz.c

**Missing mutations:**
- `fuzz_match_pattern()` does not cap str_len decrements, could loop long on crafted patterns
- Does not test ksmbd_convert_dir_info_name() which also validates names
- Does not test DFS path prefix stripping
- Missing test for path with only NUL bytes
- Stream name parsing does not test `:$DATA` (just data stream without stream name)
- No test for reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9)

**Recommended additions:**
- Add `fuzz_reserved_names()` specifically testing CON.txt, PRN, AUX.doc etc.
- Add `fuzz_dfs_prefix()` for DFS path prefix handling
- Add pattern matching with `**` (not a valid SMB wildcard, but attacker may send)

### 8. lock_request_fuzz.c

**Missing mutations:**
- Does not test lock sequence replay (LockSequenceNumber field)
- Does not test LockSequenceIndex extraction (bits 0-3 and 4-7)
- Missing CANCEL interaction (lock request being cancelled mid-flight)
- Does not test locks at OFFSET_MAX boundary (0x7FFFFFFFFFFFFFFF)
- Missing test for Length = 0 with EXCLUSIVE flag (spec says lock zero-length range)

**Recommended additions:**
- Add lock sequence validation (index 0-64, bitmap tracking)
- Add test with Offset = UINT64_MAX, Length = 1 (overflow)
- Add test with all flags set simultaneously

### 9. query_set_info_fuzz.c

**Missing mutations:**
- Does not exercise per-InfoClass specific buffer format validation
- Missing AdditionalInformation field validation for SECURITY info type
- Does not test file info classes that were recently added (FileStatInfo 0x46/0x47)
- InputBufferOffset alignment requirements not tested
- Missing round-trip test (QUERY_INFO response -> SET_INFO request)

**Recommended additions:**
- Add per-class buffer format validation (FileBasicInformation: 40 bytes, FileRenameInformation: variable, etc.)
- Add AdditionalInformation bitmask fuzzing for SECURITY type

### 10. quota_request_fuzz.c

**Missing mutations:**
- Does not test mixed ReturnSingle + SidListLength > 0 + StartSidLength > 0 (spec says SidList takes priority)
- NextEntryOffset causing backward traversal not explicitly tested (value < current offset)
- Missing test for SID with authority bytes set to unusual values

**Recommended additions:**
- Add combined SidList + StartSid test (priority logic)
- Add SID with authority = {0,0,0,0,0,0} (null authority)

### 11. reparse_point_fuzz.c

**Missing mutations:**
- Does not test IO_REPARSE_TAG_NFS (has its own structure: NfsType, then type-specific data)
- Does not test overlapping SubstituteName and PrintName regions
- Missing validation that SubstituteName is valid UTF-16LE
- Does not test ReparseDataLength = 0 with SYMLINK tag
- Missing FSCTL_DELETE_REPARSE_POINT input validation (just ReparseTag + ReparseDataLength=0 + Reserved)

**Recommended additions:**
- Add NFS reparse tag (NFS_SPECFILE_LNK, NFS_SPECFILE_CHR, etc.)
- Add overlapping SubstituteName/PrintName regions
- Add DELETE_REPARSE_POINT input fuzzing

### 12. dfs_referral_fuzz.c

**Missing mutations:**
- Does not test DFS_GET_REFERRALS_EX (extended format with additional fields)
- Does not test RequestFileName with path separator counting (component extraction)
- Missing multi-component path: `\server\share\path\to\file`
- Does not test case sensitivity of server/share components
- Missing test for odd-length filename (not properly aligned for Unicode)

**Recommended additions:**
- Add DFS_GET_REFERRALS_EX input format fuzzing
- Add multi-component path parsing
- Add ASCII fallback path (SMB1 DFS)

### 13. transform_header_fuzz.c

**Missing mutations:**
- Does not validate OriginalMessageSize consistency with actual encrypted payload
- Does not test compound encrypted messages (multiple SMB2 messages after transform header)
- Missing encryption algorithm-specific nonce requirements (AES-CCM nonce format vs AES-GCM)
- Does not test EncryptionAlgorithm field (SMB 3.1.1)
- No test for transform header followed by another transform header (nested encryption)

**Recommended additions:**
- Add compound-after-transform test (OriginalMessageSize covers multiple requests)
- Add algorithm-nonce validation (11-byte nonce for CCM, 12-byte for GCM)
- Add nested transform header rejection test


## Corpus & Dictionary

### Seed Corpus Sources

1. **pcap captures**: Use `smbclient` and `smbclient -m SMB1` against ksmbd to capture valid packets. Extract individual PDU payloads using tshark:
   ```bash
   tshark -r capture.pcap -Y "smb2" -T fields -e smb2.payload_data > seed_smb2.bin
   ```

2. **smbtorture packet logs**: Run specific smbtorture subtests (smb2.negotiate, smb2.session, smb2.create, smb2.compound, smb2.lock) with packet capture enabled.

3. **Manual seed construction**: For each harness, create 5-10 hand-crafted seeds:
   - Minimal valid input (smallest valid packet)
   - Maximum valid input (all optional fields present)
   - Known edge cases from bug fixes (see MEMORY.md Fixed Issues)

4. **Protocol specification examples**: Extract example packets from MS-SMB2, MS-SPNG, MS-NLMP, MS-XCA specification appendices.

### Protocol-Aware Dictionaries

Create AFL/libFuzzer dictionaries for structure-aware mutation:

**smb2_dict.txt** -- protocol constants:
```
# Protocol IDs
"\xFE\x53\x4D\x42"    # SMB2 ProtocolId
"\xFD\x53\x4D\x42"    # Transform ProtocolId
"\xFC\x53\x4D\x42"    # Compression ProtocolId
"\xFF\x53\x4D\x42"    # SMB1 ProtocolId

# SMB2 Commands (2 bytes LE)
"\x00\x00"             # NEGOTIATE
"\x01\x00"             # SESSION_SETUP
"\x03\x00"             # TREE_CONNECT
"\x05\x00"             # CREATE
"\x06\x00"             # CLOSE
"\x08\x00"             # READ
"\x09\x00"             # WRITE
"\x0A\x00"             # LOCK
"\x0B\x00"             # IOCTL
"\x0C\x00"             # CANCEL
"\x0E\x00"             # QUERY_DIRECTORY
"\x0F\x00"             # CHANGE_NOTIFY
"\x10\x00"             # QUERY_INFO
"\x11\x00"             # SET_INFO

# Structure sizes (2 bytes LE)
"\x40\x00"             # SMB2 header (64)
"\x24\x00"             # NEGOTIATE req (36)
"\x19\x00"             # SESSION_SETUP req (25)
"\x09\x00"             # TREE_CONNECT req (9)
"\x39\x00"             # CREATE req (57)
"\x18\x00"             # CLOSE req (24)
"\x31\x00"             # READ req (49)
"\x31\x00"             # WRITE req (49)
"\x30\x00"             # LOCK req (48)
"\x39\x00"             # IOCTL req (57)
"\x04\x00"             # CANCEL req (4)
"\x21\x00"             # SET_INFO req (33)
"\x29\x00"             # QUERY_INFO req (41)

# Negotiate context types (2 bytes LE)
"\x01\x00"             # PREAUTH_INTEGRITY
"\x02\x00"             # ENCRYPTION
"\x03\x00"             # COMPRESSION
"\x05\x00"             # NETNAME
"\x06\x00"             # TRANSPORT
"\x07\x00"             # RDMA_TRANSFORM
"\x08\x00"             # SIGNING

# Dialects (2 bytes LE)
"\x02\x02"             # SMB 2.0.2
"\x10\x02"             # SMB 2.1
"\x00\x03"             # SMB 3.0
"\x02\x03"             # SMB 3.0.2
"\x11\x03"             # SMB 3.1.1
"\xFF\x02"             # SMB2 wildcard

# FSCTL codes (4 bytes LE)
"\x90\x01\x14\x00"    # FSCTL_VALIDATE_NEGOTIATE_INFO
"\x60\x01\x14\x00"    # FSCTL_COPYCHUNK
"\x7C\x01\x14\x00"    # FSCTL_COPYCHUNK_WRITE
"\x44\x00\x09\x00"    # FSCTL_SET_REPARSE_POINT
"\x54\x00\x09\x00"    # FSCTL_QUERY_ALLOCATED_RANGES
"\x64\x00\x09\x00"    # FSCTL_SET_ZERO_DATA
"\x1C\x00\x09\x00"    # FSCTL_PIPE_TRANSCEIVE
"\x04\x03\x09\x00"    # FSCTL_SVHDX_SYNC_TUNNEL
"\x41\x00\x06\x00"    # FSCTL_DFS_GET_REFERRALS
"\x60\x00\x09\x00"    # FSCTL_SET_SPARSE
"\x0C\x01\x14\x00"    # FSCTL_SRV_REQUEST_RESUME_KEY

# NTLMSSP constants
"NTLMSSP\x00"         # Signature
"\x01\x00\x00\x00"    # NEGOTIATE_MESSAGE
"\x02\x00\x00\x00"    # CHALLENGE_MESSAGE
"\x03\x00\x00\x00"    # AUTHENTICATE_MESSAGE

# ASN.1 / SPNEGO
"\x60"                 # Application 0 (SPNEGO init)
"\xa0"                 # Context 0
"\xa1"                 # Context 1
"\xa2"                 # Context 2
"\x30"                 # SEQUENCE
"\x06"                 # OID
"\x04"                 # OCTET STRING

# Create context tags
"DH2Q"                 # Durable Handle V2 Request
"DH2C"                 # Durable Handle V2 Reconnect
"DHnQ"                 # Durable Handle Request
"DHnC"                 # Durable Handle Reconnect
"MxAc"                 # Maximum Access
"QFid"                 # Query on Disk ID
"RqLs"                 # Request Lease
"AAPL"                 # Apple Extensions

# Reparse tags (4 bytes LE)
"\x0C\x00\x00\xA0"    # IO_REPARSE_TAG_SYMLINK
"\x03\x00\x00\xA0"    # IO_REPARSE_TAG_MOUNT_POINT
"\x14\x00\x00\x80"    # IO_REPARSE_TAG_NFS

# Compression algorithms (2 bytes LE)
"\x00\x00"             # NONE
"\x01\x00"             # LZNT1
"\x02\x00"             # LZ77
"\x03\x00"             # LZ77+Huffman
"\x04\x00"             # PATTERN_V1

# Lock flags (4 bytes LE)
"\x01\x00\x00\x00"    # SHARED_LOCK
"\x02\x00\x00\x00"    # EXCLUSIVE_LOCK
"\x04\x00\x00\x00"    # UNLOCK
"\x10\x00\x00\x00"    # FAIL_IMMEDIATELY

# Info types
"\x01"                 # FILE
"\x02"                 # FILESYSTEM
"\x03"                 # SECURITY
"\x04"                 # QUOTA
```

**smb1_dict.txt** -- SMB1-specific:
```
# SMB1 Protocol ID
"\xFF\x53\x4D\x42"

# Dialect strings
"\x02NT LM 0.12\x00"
"\x02NT LANMAN 1.0\x00"
"\x02SMB 2.002\x00"
"\x02SMB 2.???\x00"
"\x02PC NETWORK PROGRAM 1.0\x00"
"\x02LANMAN1.0\x00"
"\x02LANMAN2.1\x00"

# SMB1 Commands (1 byte)
"\x72"                 # NEGOTIATE
"\x73"                 # SESSION_SETUP_ANDX
"\x75"                 # TREE_CONNECT_ANDX
"\x25"                 # TRANSACTION
"\x32"                 # TRANSACTION2
"\xA0"                 # NT_TRANSACT
"\xA2"                 # NT_CREATE_ANDX
"\x2E"                 # READ_ANDX
"\x2F"                 # WRITE_ANDX
"\x24"                 # LOCKING_ANDX

# AndX chain markers
"\xFF"                 # No AndX (chain terminator)
```

**quic_dict.txt** -- QUIC-specific:
```
# QUIC version
"\x00\x00\x00\x01"    # Version 1

# First byte patterns
"\xC0"                 # Long header, Initial
"\xC1"                 # Long header, Initial (alt)
"\xD0"                 # Long header, 0-RTT
"\xE0"                 # Long header, Handshake
"\xF0"                 # Long header, Retry
"\x40"                 # Short header
```

**compression_dict.txt** -- Compression-specific:
```
# LZNT1 chunk headers (2 bytes LE)
"\x03\xB0"             # Compressed chunk, 4 bytes data
"\xFF\xBF"             # Compressed chunk, max size
"\x00\x30"             # Uncompressed chunk, 1 byte

# LZ77 flag bytes
"\x00"                 # All literals
"\xFF"                 # All matches
```

### Recommended Fuzzing Infrastructure

1. **In-kernel harnesses** (current approach): Load as test modules, suitable for syzkaller integration. Each module exports an ioctl or debugfs entry point that accepts (data, len).

2. **Userspace harnesses** (recommended addition): Extract the parsing functions into userspace-compilable form using `#ifdef __KERNEL__` guards. This enables:
   - libFuzzer (`-fsanitize=fuzzer`) for coverage-guided fuzzing
   - AFL++ with ASAN/MSAN for memory error detection
   - OSS-Fuzz integration

3. **Coverage guidance**: Build ksmbd with `CONFIG_GCOV_KERNEL=y` and use kcov/syzkaller for kernel-side coverage feedback.

4. **Regression corpus**: After each bug fix, add the crashing input to the seed corpus as a regression test.

### Priority Order for Implementation

| Priority | Harness | Rationale |
|----------|---------|-----------|
| P0 | compression_fuzz.c | New code, complex parsing, decompression bombs |
| P0 | session_setup_fuzz.c | Pre-auth, unauthenticated, historically vulnerable |
| P0 | quic_packet_fuzz.c | New code, unauthenticated UDP, first bytes on wire |
| P0 | compound_request_fuzz.c | State confusion, FID propagation bugs proven |
| P1 | smb1_pdu_fuzz.c | Large attack surface, legacy code |
| P1 | negotiate_request_fuzz.c | Unauthenticated, dialect/context interaction |
| P1 | ea_buffer_fuzz.c | Chained structure, OOB read history |
| P1 | copychunk_fuzz.c | Complex validation, chunk count overflow |
| P1 | validate_negotiate_fuzz.c | Unauthenticated FSCTL, disconnect trigger |
| P2 | rsvd_tunnel_fuzz.c | Nested protocol, SCSI passthrough |
| P2 | ipc_netlink_fuzz.c | Trust boundary (kernel<->userspace) |
| P2 | unicode_conversion_fuzz.c | Used everywhere, surrogate pair edge cases |
| P2 | filename_fuzz.c | Path traversal, device name bypass |
| P2 | share_name_fuzz.c | UTF-16 extraction, length limits |
| P2 | tree_connect_fuzz.c | Extension parsing, offset math |
| P2 | wildcard_fuzz.c | Algorithmic complexity, DOS wildcards |
| P3 | smb3_compression_header_fuzz.c | Header-level (data already covered) |
| P3 | pipe_transceive_fuzz.c | Named pipe / DCE-RPC |
| P3 | oplock_lease_fuzz.c | Create context subtype |
| P3 | app_instance_fuzz.c | Simple structure, lower risk |
