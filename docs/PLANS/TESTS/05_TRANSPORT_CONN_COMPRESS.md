# Test Plan: Transport, Connection, Compression & Encoding

## Current Coverage Summary

### ksmbd_test_conn_hash.c (10 tests)
Tests the connection hash table logic via replicated pure-logic functions
(does NOT link to ksmbd module):

| Test | What it covers |
|------|---------------|
| `test_hash_init_all_empty` | All 256 buckets empty after init |
| `test_hash_add_makes_nonempty` | Single add makes table non-empty |
| `test_hash_add_del_restores_empty` | Add+delete cycle returns to empty |
| `test_hash_multiple_same_bucket` | Two entries with same key share one bucket |
| `test_hash_multiple_different_buckets` | Different keys land in different buckets |
| `test_hash_del_from_empty_bucket` | Delete on never-added entry is safe |
| `test_hash_del_twice_safe` | Double-delete via hlist_del_init is safe |
| `test_hash_bucket_index_range` | hash_min() result always in [0, 255] |
| `test_hash_size_is_power_of_two` | CONN_HASH_SIZE == 256, is power of 2 |
| `test_hash_add_many_entries` | 16 entries add/remove cycle |

**Gaps**: No concurrency tests, no collision chain verification, no
atomic counter (conn_hash_count) tests, no per-IP counting logic,
no connection lifecycle.

### ksmbd_test_ndr.c (5 tests)
Tests NDR encoding/decoding for `xattr_dos_attrib` structures:

| Test | What it covers |
|------|---------------|
| `test_ndr_encode_decode_dos_attr_v4` | Round-trip version 4 |
| `test_ndr_encode_decode_dos_attr_v3` | Round-trip version 3 |
| `test_ndr_decode_dos_attr_truncated` | Truncated buffer rejection |
| `test_ndr_decode_dos_attr_bad_version` | Invalid version (5) rejection |
| `test_ndr_decode_dos_attr_version_mismatch` | Version field mismatch rejection |

**Gaps**: No POSIX ACL encode tests (`ndr_encode_posix_acl`), no
NT ACL encode/decode tests (`ndr_encode_v4_ntacl` / `ndr_decode_v4_ntacl`),
no POSIX ACL entry encode tests, no alignment/padding boundary tests,
no overflow/realloc tests.

### ksmbd_test_unicode.c (19 tests)
Tests character validation and UTF-16LE encoding helpers via
replicated pure-logic functions:

| Test | What it covers |
|------|---------------|
| 8 `is_char_allowed_*` tests | Allowed/banned character classes |
| 4 `utf16_name_length_*` tests | SMB1 UTF-16 string length counting |
| 3 `utf16_bytes_*` tests | Simplified byte counting |
| 4 `utf16le_encoding_*` tests | cpu_to_le16 encoding basics |

**Gaps**: No `smb_from_utf16()` conversion tests, no `smb_strtoUTF16()` tests,
no `smbConvertToUTF16()` tests, no `smb_strndup_from_utf16()` tests,
no surrogate pair handling, no overlong UTF-8 sequence detection, no
embedded null byte tests, no max-length boundary tests, no `cifs_mapchar()`
special character remapping tests.

### Files with ZERO test coverage

| Source File | Functions | Test File |
|-------------|-----------|-----------|
| `src/transport/transport_tcp.c` | 20+ functions | NONE |
| `src/transport/transport_rdma.c` | 50+ functions | NONE |
| `src/transport/transport_ipc.c` | 30+ functions | NONE |
| `src/transport/transport_quic.c` | 40+ functions | NONE |
| `src/core/connection.c` | 20+ exported functions | Only hash table subset |
| `src/core/smb2_compress.c` | 20+ functions (5 algorithms) | NONE |
| `src/core/ksmbd_work.c` | 10 exported functions | NONE |
| `src/core/server.c` | 10+ exported functions | NONE |
| `src/encoding/asn1.c` | 8 exported functions | NONE |

---

## Gap Analysis

### Critical Gaps (security/correctness impact)

1. **Compression algorithms** - Zero tests for LZNT1, LZ77, LZ77+Huffman,
   Pattern_V1. These parse untrusted client data and are primary targets
   for buffer overflow and DoS attacks. Round-trip correctness is unverified.

2. **QUIC crypto** - HKDF key derivation, AEAD encrypt/decrypt, header
   protection, varint encoding/decoding are untested. Protocol state
   machine transitions unverified.

3. **ASN.1/SPNEGO parsing** - Handles untrusted authentication blobs from
   clients. OID decoding, SPNEGO token construction, truncated input
   handling all untested.

4. **IPC message validation** - `ipc_validate_msg()` checks payload sizes
   for 4 different message types but is never tested with crafted inputs.

5. **Connection state machine** - State transitions (NEW, GOOD, EXITING,
   RELEASING), refcount lifecycle, and the interaction between hash table
   and connection cleanup are completely untested.

### High-Priority Gaps

6. **kvec_array_init** - Core TCP I/O scatter-gather logic has no tests
   for partial reads, zero-length segments, or boundary conditions.

7. **Work struct lifecycle** - Allocation, IOV pinning, reallocation,
   compound work chaining, and async ID management are untested.

8. **NDR POSIX ACL and NT ACL** - Complex multi-field structures with
   alignment requirements; encode/decode round-trips not tested.

9. **Unicode conversion paths** - The actual `smb_from_utf16()` and
   `smbConvertToUTF16()` functions (with NLS table dependency) are
   untested. Surrogate pairs and multi-byte edge cases unverified.

10. **Per-IP connection limiting** - The connection rate-limiting logic
    in `ksmbd_kthread_fn()` is security-critical and untested.

---

## New Tests Required

### ksmbd_test_conn_hash.c Enhancements

These can be added to the existing test file since they use the same
replicated hash logic and do not require linking to the ksmbd module.

#### Hash distribution quality
```
test_hash_distribution_uniformity
  - Add 1024 entries with sequential keys 0..1023
  - Verify no single bucket has more than ~16 entries (4x mean)
  - Ensures hash_min() provides reasonable spread
```

#### Collision chain integrity
```
test_hash_collision_chain_ordering
  - Force 10 entries to the same bucket (key=0)
  - Verify iteration finds all 10 in the chain
  - Remove middle entry, verify chain still intact with 9

test_hash_collision_chain_head_removal
  - Force 3 entries to same bucket
  - Remove the HEAD entry
  - Verify remaining 2 entries still accessible
```

#### Atomic counter tests
```
test_hash_atomic_count_tracks_adds
  - Replicate the conn_hash_count atomic from connection.c
  - Add N entries, verify count == N
  - Remove all, verify count == 0

test_hash_atomic_count_del_idempotent
  - Add 1 entry, delete it twice
  - Verify count == 0 (not -1)
```

#### Concurrent add/remove (stress)
```
test_hash_concurrent_add_remove
  - Spawn 4 kthreads, each adding/removing 100 entries
  - Verify final state is consistent (empty or expected count)
  - Tests spinlock correctness under contention
```

#### Overflow / extreme keys
```
test_hash_key_zero
  - Verify key=0 maps to a valid bucket

test_hash_key_max_u32
  - Verify key=0xFFFFFFFF maps to a valid bucket

test_hash_large_population
  - Add 1000 entries, verify non-empty
  - Remove all 1000, verify empty
```

---

### ksmbd_test_connection.c (NEW)

Tests connection lifecycle, refcount transitions, and state machine.
Requires replicated state machine logic or stub ksmbd_conn structs.

#### Connection allocation/cleanup
```
test_conn_alloc_basic
  - Allocate ksmbd_conn via ksmbd_conn_alloc()
  - Verify default field values:
    - need_neg == true
    - status == KSMBD_SESS_NEW
    - refcnt == 1
    - total_credits == 1
    - req_running == 0
  - Free via ksmbd_conn_free()

test_conn_alloc_null_nls_fallback
  - If "utf8" NLS load fails, verify local_nls == default NLS
  - Verify um == NULL when CONFIG_UNICODE disabled
```

#### State machine transitions
```
test_conn_state_new_to_good
  - Verify ksmbd_conn_good() returns false when NEW
  - Set GOOD, verify ksmbd_conn_good() returns true

test_conn_state_good_to_exiting
  - Set GOOD, then set EXITING
  - Verify ksmbd_conn_alive() returns false
  - Verify ksmbd_conn_exiting() returns true

test_conn_state_exiting_to_releasing
  - Set EXITING, then RELEASING
  - Verify ksmbd_conn_releasing() returns true

test_conn_state_cannot_go_backwards
  - Set EXITING, try to set GOOD
  - Verify state remains EXITING (if the implementation enforces this)
```

#### Refcount transitions
```
test_conn_refcount_init_is_one
  - Allocate conn, verify refcount_read() == 1

test_conn_refcount_inc_dec
  - refcount_inc(), verify == 2
  - ksmbd_conn_free() (dec), verify conn still alive (count == 1)
  - ksmbd_conn_free() again, verify cleanup runs

test_conn_refcount_inc_not_zero_on_zero
  - After final free, refcount_inc_not_zero() should return false
```

#### Request enqueue/dequeue
```
test_conn_enqueue_increments_req_running
  - Create stub work with non-CANCEL command
  - ksmbd_conn_enqueue_request()
  - Verify req_running == 1

test_conn_dequeue_decrements_req_running
  - Enqueue then dequeue
  - Verify req_running == 0

test_conn_cancel_not_queued
  - Create stub work with SMB2_CANCEL command
  - ksmbd_conn_enqueue_request()
  - Verify request NOT on requests list (but req_running still incremented)
```

#### r_count lifecycle
```
test_conn_r_count_inc_dec
  - ksmbd_conn_r_count_inc()
  - Verify r_count == 1
  - ksmbd_conn_r_count_dec()
  - Verify r_count == 0

test_conn_r_count_dec_wakes_waiter
  - Inc r_count to 1
  - Set up a waiter on r_count_q
  - Dec to 0 in another context
  - Verify waiter was woken
```

#### Connection hash with real conn structs
```
test_conn_hash_add_del_with_real_conn
  - Allocate conn, set inet_hash
  - ksmbd_conn_hash_add(), verify not empty
  - ksmbd_conn_hash_del(), verify empty

test_conn_hash_del_already_removed
  - Add conn, del twice
  - Verify no crash, hash is empty

test_conn_lookup_dialect_finds_matching_guid
  - Add two conns with different GUIDs
  - ksmbd_conn_lookup_dialect() with matching GUID returns true
  - With non-matching GUID returns false
```

#### Per-IP connection limits
```
test_conn_per_ip_limit_enforced
  - Set server_conf.max_ip_connections = 2
  - Add 2 conns with same inet_hash/inet_addr
  - Verify 3rd connection attempt would exceed limit

test_conn_per_ip_limit_excludes_exiting
  - Add 3 conns, set 1 to EXITING
  - Verify only 2 counted toward limit

test_conn_per_ip_limit_zero_means_unlimited
  - Set server_conf.max_ip_connections = 0
  - Verify no limit enforcement
```

#### ksmbd_conn_alive edge cases
```
test_conn_alive_false_when_server_not_running
  - Set server state to not running
  - Verify ksmbd_conn_alive() == false

test_conn_alive_true_with_open_files
  - Set open_files_count > 0
  - Verify alive even after deadtime expired

test_conn_alive_false_after_deadtime
  - Set deadtime to small value
  - Set last_active to jiffies - deadtime - 1
  - Set open_files_count = 0
  - Verify alive == false
```

---

### ksmbd_test_transport_tcp.c (NEW)

Tests for pure-logic TCP transport functions that can be replicated
without actual socket operations.

#### kvec_array_init tests
```
test_kvec_array_init_single_segment
  - 1 segment of 100 bytes, offset 0
  - Verify output == input

test_kvec_array_init_partial_first_segment
  - 1 segment of 100 bytes, offset 50
  - Verify output base adjusted by 50, len reduced by 50

test_kvec_array_init_skip_entire_first_segment
  - 2 segments: 100, 200 bytes. offset = 100
  - Verify output starts at segment 2

test_kvec_array_init_partial_second_segment
  - 2 segments: 100, 200 bytes. offset = 150
  - Verify output starts 50 bytes into segment 2

test_kvec_array_init_all_consumed
  - 1 segment of 100 bytes, offset = 100
  - Verify returns 0 segments

test_kvec_array_init_zero_length_segment
  - Segment with iov_len = 0 in the middle
  - Verify skipped correctly

test_kvec_array_init_many_segments
  - 8 segments, various sizes, offset spanning 3 segments
  - Verify correct starting segment and offset
```

#### Socket option verification (mock/stub based)
```
test_tcp_nodelay_called
  - Verify ksmbd_tcp_nodelay() sets TCP_NODELAY on socket

test_tcp_keepalive_params
  - Verify keepidle=120, keepintvl=30, keepcnt=3

test_tcp_reuseaddr_called
  - Verify SO_REUSEADDR set
```

#### Transport allocation/free
```
test_alloc_transport_null_socket
  - Pass NULL socket, expect NULL return

test_alloc_transport_valid
  - Allocate transport with mock socket
  - Verify conn allocated, hash added, transport ops set

test_free_transport_releases_resources
  - Allocate then free
  - Verify socket released, iov freed, struct freed
```

#### Connection teardown
```
test_disconnect_decrements_active_count
  - Set max_connections > 0
  - Allocate transport (increments active_num_conn)
  - Disconnect, verify decremented

test_disconnect_no_decrement_when_max_zero
  - Set max_connections = 0
  - Disconnect, verify no decrement
```

#### Interface management
```
test_alloc_iface_null_name
  - alloc_iface(NULL) returns NULL

test_alloc_iface_valid
  - alloc_iface("eth0") returns non-NULL
  - Verify name set, state == IFACE_STATE_DOWN

test_find_netdev_name_iface
  - Add iface "eth0", find it by name
  - Search for "eth1" returns NULL

test_tcp_set_interfaces_empty
  - ksmbd_tcp_set_interfaces(NULL, 0)
  - Verify bind_additional_ifaces == 1

test_tcp_set_interfaces_list
  - ksmbd_tcp_set_interfaces("eth0\0eth1", 10)
  - Verify two ifaces created
```

---

### ksmbd_test_transport_ipc.c (NEW)

Tests for IPC message construction, validation, and handling logic.

#### Message allocation
```
test_ipc_msg_alloc_basic
  - Allocate message of 100 bytes
  - Verify msg->sz == 100, payload zeroed

test_ipc_msg_alloc_overflow
  - Allocate with sz = SIZE_MAX
  - Verify returns NULL (overflow check)

test_ipc_msg_alloc_zero
  - Allocate with sz = 0
  - Verify returns valid (empty payload)
```

#### Message validation (ipc_validate_msg)
```
test_ipc_validate_rpc_response_correct_size
  - Construct valid RPC response with payload_sz matching msg_sz
  - Verify returns 0

test_ipc_validate_rpc_response_overflow
  - Construct RPC response with payload_sz causing overflow
  - Verify returns -EINVAL

test_ipc_validate_spnego_response_correct
  - Construct valid SPNEGO response
  - Verify returns 0

test_ipc_validate_spnego_response_overflow
  - session_key_len + spnego_blob_len overflows
  - Verify returns -EINVAL

test_ipc_validate_share_config_response_correct
  - Construct valid share config response
  - Verify returns 0

test_ipc_validate_share_config_veto_list_overflow
  - payload_sz < veto_list_sz
  - Verify returns -EINVAL

test_ipc_validate_share_config_veto_equal_payload
  - veto_list_sz > 0 && payload_sz == veto_list_sz (no path)
  - Verify returns -EINVAL

test_ipc_validate_login_ext_correct
  - Construct valid login_ext response with ngroups
  - Verify returns 0

test_ipc_validate_login_ext_groups_overflow
  - ngroups causing multiplication overflow
  - Verify returns -EINVAL

test_ipc_validate_max_payload
  - msg_sz > KSMBD_IPC_MAX_PAYLOAD
  - Verify returns -EINVAL

test_ipc_validate_unknown_type
  - Unknown message type
  - Verify returns 0 (default case)
```

#### Response handling (handle_response)
```
test_handle_response_payload_too_small
  - Payload < sizeof(unsigned int)
  - Verify returns -EINVAL

test_handle_response_type_mismatch
  - Entry type + 1 != response type
  - Verify response not delivered

test_handle_response_valid
  - Matching handle and type
  - Verify response delivered and waiter woken
```

#### Event type constants
```
test_ipc_event_types_contiguous
  - Verify KSMBD_EVENT_* values form a contiguous range
  - Verify policy array covers all events

test_ipc_genl_ops_coverage
  - Verify every KSMBD_EVENT has a matching genl_op
```

---

### ksmbd_test_transport_quic.c (NEW)

Tests for QUIC-specific pure-logic functions.

#### Variable-length integer encoding/decoding (RFC 9000 Section 16)
```
test_quic_varint_encode_1byte
  - Values 0..63 encode to 1 byte
  - Verify encoding and decoded value match

test_quic_varint_encode_2byte
  - Values 64..16383 encode to 2 bytes
  - Verify prefix bits = 0b01

test_quic_varint_encode_4byte
  - Values 16384..1073741823 encode to 4 bytes
  - Verify prefix bits = 0b10

test_quic_varint_encode_8byte
  - Values > 1073741823 encode to 8 bytes
  - Verify prefix bits = 0b11

test_quic_varint_roundtrip
  - Encode then decode for boundary values: 0, 63, 64, 16383, 16384,
    1073741823, 1073741824, 4611686018427387903 (max)

test_quic_varint_decode_truncated
  - 2-byte varint in 1-byte buffer
  - Verify returns error

test_quic_varint_decode_all_zeros
  - Verify decodes to 0
```

#### HKDF key derivation (RFC 9001 Section 5)
```
test_quic_hkdf_expand_label_known_vector
  - Use RFC 9001 Appendix A test vectors for Initial secret derivation
  - Verify client_initial_secret matches expected value

test_quic_hkdf_expand_label_empty_context
  - Label with empty context hash info
  - Verify output matches expected

test_quic_derive_initial_secrets
  - Use known DCID from RFC 9001 Appendix A
  - Verify client_secret and server_secret match test vectors
  - Verify client_key, client_iv, server_key, server_iv match

test_quic_derive_initial_secrets_v2
  - QUIC Version 2 initial salt (if supported)
  - Verify different output from v1
```

#### AEAD encrypt/decrypt (AES-128-GCM)
```
test_quic_aead_roundtrip
  - Encrypt then decrypt a test payload
  - Verify plaintext matches original

test_quic_aead_bad_tag
  - Encrypt, flip 1 bit in ciphertext
  - Verify decrypt fails

test_quic_aead_nonce_construction
  - Verify nonce = base_iv XOR packet_number (zero-padded)
  - Test with packet numbers 0, 1, 0xFFFFFFFF

test_quic_aead_empty_payload
  - Encrypt/decrypt empty AAD-only packet
  - Verify header bytes preserved as AAD
```

#### Header protection (RFC 9001 Section 5.4)
```
test_quic_header_protection_mask
  - Compute AES-ECB(hp_key, sample) for known inputs
  - Verify 5-byte mask matches expected

test_quic_header_protect_unprotect_roundtrip
  - Apply header protection then remove it
  - Verify original header restored

test_quic_header_protection_long_header
  - Long header: mask applied to 4 bits of first byte + packet number
  - Verify correct bit manipulation

test_quic_header_protection_short_header
  - Short header: mask applied to 5 bits of first byte + packet number
  - Verify correct bit manipulation
```

#### QUIC connection hash
```
test_quic_dcid_hash_basic
  - Compute hash for known DCID
  - Verify deterministic

test_quic_dcid_hash_different_dcids
  - Different DCIDs produce different hashes

test_quic_conn_insert_remove
  - Insert qconn, verify findable by DCID
  - Remove, verify not findable
```

#### QUIC state machine
```
test_quic_state_initial_to_handshake
  - New connection starts in INITIAL
  - After processing ClientHello, transitions to HANDSHAKE

test_quic_state_handshake_to_connected
  - After installing 1-RTT keys, transitions to CONNECTED

test_quic_state_connected_to_closing
  - After CONNECTION_CLOSE frame, transitions to CLOSING

test_quic_state_invalid_transition
  - CONNECTED cannot go back to INITIAL
```

#### Initial packet parsing
```
test_quic_parse_initial_valid
  - Construct valid QUIC Initial packet with known structure
  - Verify DCID, SCID, version, token, and payload extracted correctly

test_quic_parse_initial_too_short
  - Packet shorter than minimum (< 1200 bytes for client)
  - Verify returns error

test_quic_parse_initial_bad_version
  - Set version to unknown value
  - Verify triggers version negotiation

test_quic_parse_initial_truncated_dcid
  - DCID length exceeds packet
  - Verify returns error
```

#### CRYPTO frame parsing
```
test_quic_parse_crypto_frame_basic
  - Valid CRYPTO frame with offset=0 and known data
  - Verify extracted payload matches

test_quic_parse_crypto_frame_nonzero_offset
  - CRYPTO frame with offset > 0
  - Verify correct reassembly position

test_quic_parse_crypto_frame_truncated
  - Frame length exceeds packet boundary
  - Verify returns error
```

#### Version negotiation
```
test_quic_version_negotiation_packet
  - Verify constructed VN packet contains supported versions
  - Verify correct packet structure per RFC 9000 Section 17.2.1
```

---

### ksmbd_test_compress.c (NEW)

Comprehensive compression tests for all 5 algorithms. These test the
static compression/decompression functions via wrapper helpers.

#### Pattern_V1 (Algorithm 0x0004)
```
test_pattern_v1_all_same_byte
  - 4096 bytes of 0xAA
  - Compress, verify output == 8 bytes (pattern_v1_payload)
  - Decompress, verify matches original

test_pattern_v1_single_byte
  - 1 byte: 0x42
  - Verify not compressed (compressed size >= original)

test_pattern_v1_all_zeros
  - 4096 bytes of 0x00
  - Compress and round-trip

test_pattern_v1_mixed_bytes
  - 4096 bytes with byte[100] different
  - Verify returns 0 (not compressible)

test_pattern_v1_empty_input
  - 0 bytes
  - Verify returns 0

test_pattern_v1_dst_too_small
  - Valid pattern, but dst_len < 8
  - Verify returns 0

test_pattern_v1_decompress_truncated
  - Valid compressed data truncated to 4 bytes
  - Verify decompression fails

test_pattern_v1_decompress_zero_repetitions
  - Compressed payload with Repetitions = 0
  - Verify decompresses to empty
```

#### LZNT1 (Algorithm 0x0001)
```
test_lznt1_roundtrip_ascii
  - Compress "Hello World Hello World Hello World" (repeated)
  - Decompress, verify matches

test_lznt1_roundtrip_random
  - 4096 bytes of random data
  - Compress then decompress, verify matches
  - (Random data may not compress well, but round-trip must hold)

test_lznt1_roundtrip_all_zeros
  - 4096 bytes of 0x00
  - Verify significant compression ratio
  - Decompress matches

test_lznt1_roundtrip_single_byte
  - 1 byte input
  - Verify round-trip

test_lznt1_roundtrip_4096_repeated_pattern
  - 4096 bytes of repeating 16-byte pattern
  - Verify good compression and exact round-trip

test_lznt1_roundtrip_max_chunk_boundary
  - Exactly 4096 bytes (one LZNT1 chunk)
  - Verify chunk header and round-trip

test_lznt1_roundtrip_multi_chunk
  - 8192 bytes (two LZNT1 chunks)
  - Verify both chunks processed correctly

test_lznt1_decompress_malformed_chunk_header
  - Chunk header with size larger than remaining data
  - Verify returns error (not crash)

test_lznt1_decompress_infinite_loop_guard
  - Crafted input that would cause infinite loop
  - Verify terminates with error

test_lznt1_decompress_zero_length_chunk
  - Chunk header indicating 0 bytes
  - Verify terminates cleanly

test_lznt1_compress_incompressible
  - High-entropy data that cannot be compressed
  - Verify returns original size or negative

test_lznt1_large_offset_reference
  - Input designed to produce max displacement in match
  - Verify correct offset/length encoding
```

#### LZ77 Plain (Algorithm 0x0002)
```
test_lz77_roundtrip_ascii
  - Repeated text string
  - Compress, decompress, verify match

test_lz77_roundtrip_random
  - 4096 bytes of random data
  - Verify round-trip correctness

test_lz77_roundtrip_all_zeros
  - High compression expected
  - Verify round-trip

test_lz77_roundtrip_one_byte
  - Single byte
  - Verify round-trip

test_lz77_roundtrip_exactly_hash_window_size
  - Data size equals the hash table window (if applicable)
  - Verify boundary handling

test_lz77_decompress_malformed_match
  - Match offset points before start of buffer
  - Verify returns error

test_lz77_decompress_output_overflow
  - Decompressed size exceeds dst_len
  - Verify returns error (not buffer overrun)

test_lz77_decompress_truncated_input
  - Input truncated mid-match
  - Verify returns error

test_lz77_compress_empty
  - 0 bytes input
  - Verify returns 0 or empty output

test_lz77_roundtrip_large
  - 1MB of repeated pattern
  - Verify round-trip and good compression ratio
```

#### LZ77+Huffman (Algorithm 0x0003)
```
test_lz77huff_roundtrip_ascii
  - Repeated text string
  - Compress, decompress, verify match

test_lz77huff_roundtrip_random
  - 4096 bytes random data
  - Verify round-trip

test_lz77huff_roundtrip_all_zeros
  - Verify round-trip and good ratio

test_lz77huff_roundtrip_one_byte
  - Single byte
  - Verify round-trip

test_lz77huff_roundtrip_256_distinct
  - All 256 byte values exactly once
  - Verify round-trip (tests symbol coverage)

test_lz77huff_decompress_malformed_huffman_table
  - Invalid Huffman table prefix code lengths
  - Verify returns error

test_lz77huff_decompress_truncated_bitstream
  - Valid table but bitstream truncated
  - Verify returns error

test_lz77huff_decompress_output_overflow
  - Decoded data exceeds dst_len
  - Verify returns error

test_lz77huff_build_table_all_same_length
  - All 512 symbols with same code length
  - Verify table builds correctly

test_lz77huff_build_table_invalid
  - Code lengths that violate Kraft inequality
  - Verify returns error

test_lz77huff_br_refill_boundary
  - Bitstream reader at byte boundary
  - Verify correct bit extraction

test_lz77huff_decode_sym_eof
  - Read past end of bitstream
  - Verify returns special value or error

test_lz77huff_roundtrip_large
  - 1MB of mixed data
  - Verify round-trip
```

#### LZ4 (internal algorithm, not advertised)
```
test_lz4_decompress_valid
  - Compress data with LZ4, decompress via smb2_lz4_decompress
  - Verify round-trip

test_lz4_decompress_invalid
  - Garbage data as "compressed" input
  - Verify returns error

test_lz4_decompress_output_too_small
  - Valid compressed data, dst_len too small
  - Verify returns error
```

#### Cross-algorithm dispatch
```
test_compress_data_dispatches_correctly
  - Call smb2_compress_data with each algorithm ID
  - Verify correct algorithm invoked

test_decompress_data_dispatches_correctly
  - Call smb2_decompress_data with each algorithm ID
  - Verify correct algorithm invoked

test_decompress_data_unknown_algorithm
  - Algorithm ID 0xFFFF
  - Verify returns -EOPNOTSUPP or similar

test_is_compression_transform_hdr_valid
  - Buffer with SMB2_COMPRESSION_TRANSFORM protocol ID
  - Verify returns true

test_is_compression_transform_hdr_invalid
  - Buffer with SMB2 protocol ID (not compression)
  - Verify returns false
```

#### Chained compression
```
test_decompress_chained_single_chunk
  - One compression chunk in the chain
  - Verify decompresses correctly

test_decompress_chained_multiple_chunks
  - Pattern_V1 + LZNT1 chain
  - Verify both decompressed and concatenated

test_decompress_chained_truncated
  - Chain truncated mid-chunk
  - Verify returns error

test_decompress_chained_overflow
  - OriginalPayloadSize larger than max allowed
  - Verify returns error
```

#### Full SMB2 compress/decompress request/response
```
test_smb2_decompress_req_unchained
  - Construct SMB2_COMPRESSION_TRANSFORM header (unchained)
  - Set up work struct with compressed request buffer
  - Verify decompression replaces request_buf correctly

test_smb2_decompress_req_chained
  - Construct chained compression header
  - Verify decompression handles chain

test_smb2_compress_resp_when_negotiated
  - Set up conn with compression negotiated
  - Verify response gets compressed

test_smb2_compress_resp_not_negotiated
  - Compression not negotiated
  - Verify response not modified
```

---

### ksmbd_test_work.c (NEW)

Tests for ksmbd_work allocation, freeing, and IOV management.

#### Allocation and initialization
```
test_work_alloc_basic
  - ksmbd_alloc_work_struct()
  - Verify compound_fid == KSMBD_NO_FID
  - Verify lists initialized
  - Verify iov_alloc_cnt == 4
  - Verify iov != NULL

test_work_alloc_returns_null_on_oom
  - If slab cache exhausted (hard to test; verify NULL path exists)

test_work_free_releases_all_buffers
  - Set response_buf, tr_buf, request_buf to allocated memory
  - ksmbd_free_work_struct()
  - Verify no leaks (relies on kfence/kasan in CI)

test_work_free_releases_sendfile_filp
  - Set sendfile_filp to a file reference
  - Verify fput() called on free

test_work_free_releases_async_id
  - Set async_id to a valid value
  - Verify ksmbd_release_id called
```

#### IOV pinning
```
test_iov_pin_rsp_first_call
  - First pin: iov[0] gets RFC1002 header, iov[1] gets response
  - Verify iov_cnt == 2, iov_idx == 1
  - Verify RFC1002 length updated

test_iov_pin_rsp_second_call
  - Pin twice (compound response)
  - Verify iov_cnt == 3, iov_idx == 2
  - Verify RFC1002 length is cumulative

test_iov_pin_rsp_read_with_aux
  - Pin with aux_buf
  - Verify 3 iovs: RFC1002 header, response, aux_buf
  - Verify aux_read_list has entry

test_iov_pin_rsp_realloc
  - Pin 5 times to exceed initial iov_alloc_cnt of 4
  - Verify reallocation happens, no crash
  - Verify all 6 iovs accessible

test_iov_pin_rsp_realloc_failure
  - (Hard to test) Verify graceful error return on krealloc failure
```

#### Work pool lifecycle
```
test_work_pool_init_destroy
  - ksmbd_work_pool_init()
  - Allocate and free 100 work structs
  - ksmbd_work_pool_destroy()
  - Verify no leaks

test_workqueue_init_destroy
  - ksmbd_workqueue_init()
  - ksmbd_queue_work() with stub work
  - ksmbd_workqueue_destroy()
```

#### Interim response buffer
```
test_allocate_interim_rsp_buf
  - allocate_interim_rsp_buf()
  - Verify response_buf != NULL
  - Verify response_sz == MAX_CIFS_SMALL_BUFFER_SIZE
```

---

### ksmbd_test_server.c (NEW)

Tests for server configuration, request dispatch, and state management.

#### Server configuration
```
test_server_conf_set_netbios_name
  - ksmbd_set_netbios_name("TESTSERVER")
  - Verify ksmbd_netbios_name() == "TESTSERVER"

test_server_conf_set_server_string
  - ksmbd_set_server_string("Test Server")
  - Verify ksmbd_server_string() == "Test Server"

test_server_conf_set_work_group
  - ksmbd_set_work_group("TESTWORKGROUP")
  - Verify ksmbd_work_group() == "TESTWORKGROUP"

test_server_conf_set_null_value
  - ksmbd_set_netbios_name(NULL)
  - Verify returns -EINVAL

test_server_conf_set_empty_value
  - ksmbd_set_netbios_name("")
  - Verify returns -EINVAL

test_server_conf_set_replaces_previous
  - Set "A", then set "B"
  - Verify returns "B" (and "A" was freed)
```

#### Server state machine
```
test_server_state_startup
  - server_conf_init()
  - Verify state == SERVER_STATE_STARTING_UP

test_server_state_running
  - server_ctrl_handle_init (after transport init)
  - Verify state == SERVER_STATE_RUNNING

test_server_configurable
  - In STARTING_UP state
  - Verify ksmbd_server_configurable() == true

test_server_configurable_false_when_resetting
  - In RESETTING state
  - Verify ksmbd_server_configurable() == false

test_server_running_check
  - In RUNNING state
  - Verify ksmbd_server_running() == true
```

#### Request dispatch (__process_request)
```
test_process_request_invalid_command
  - Command >= max_cmds
  - Verify STATUS_INVALID_PARAMETER set

test_process_request_unimplemented
  - Command with NULL proc handler
  - Verify STATUS_NOT_IMPLEMENTED set

test_process_request_signature_check_fail
  - Sign required but check fails
  - Verify STATUS_ACCESS_DENIED set
```

#### Compound request handling
```
test_compound_error_propagation_from_create
  - First request (CREATE) fails
  - Verify subsequent related requests get same error

test_compound_no_propagation_from_write
  - CREATE succeeds, WRITE fails
  - Verify next request executes independently

test_compound_unrelated_independent
  - Non-related compound requests
  - Verify each gets independent processing
```

#### Encryption enforcement
```
test_encrypted_session_unencrypted_request_rejected
  - Session with enc_forced=true, work->encrypted=false
  - Verify STATUS_ACCESS_DENIED for non-NEGOTIATE commands

test_encrypted_session_negotiate_allowed
  - Same setup but command=NEGOTIATE
  - Verify not rejected

test_encrypted_session_session_setup_allowed
  - Same setup but command=SESSION_SETUP
  - Verify not rejected
```

---

### ksmbd_test_ndr.c Enhancements

#### POSIX ACL encoding
```
test_ndr_encode_posix_acl_empty
  - Encode with no ACL and no default ACL
  - Verify output has NULL ref_ids for both

test_ndr_encode_posix_acl_user_entry
  - Encode ACL with SMB_ACL_USER entry
  - Decode and verify uid preserved

test_ndr_encode_posix_acl_group_entry
  - Encode ACL with SMB_ACL_GROUP entry
  - Decode and verify gid preserved

test_ndr_encode_posix_acl_mixed
  - Multiple ACL entries (user, group, other)
  - Verify all preserved after encode

test_ndr_encode_posix_acl_with_default
  - Both access ACL and default ACL
  - Verify both encoded in output

test_ndr_encode_posix_acl_alignment
  - Verify 8-byte alignment maintained between entries
```

#### NT ACL v4 encoding/decoding
```
test_ndr_encode_decode_v4_ntacl_roundtrip
  - Encode ntacl v4, decode, verify all fields match
  - hash, hash_type, desc, current_time, posix_acl_hash, sd_buf

test_ndr_decode_v4_ntacl_wrong_version
  - Encode v4, patch version to 3
  - Verify decode returns -EINVAL

test_ndr_decode_v4_ntacl_truncated
  - Truncate buffer before sd_buf
  - Verify returns -EINVAL

test_ndr_decode_v4_ntacl_bad_desc
  - Patch desc to not contain "posix_acl"
  - Verify returns -EINVAL

test_ndr_decode_v4_ntacl_zero_sd_size
  - Buffer ends exactly at posix_acl_hash
  - Verify returns -EINVAL
```

#### NDR primitive write/read stress
```
test_ndr_write_int16_realloc
  - Start with empty NDR, write 600 int16 values
  - Verify all values readable after decode

test_ndr_write_int32_alignment
  - Write int16 then int32
  - Verify offset and data correct

test_ndr_write_int64_large_values
  - Write/read 0, 0xFFFFFFFFFFFFFFFF, 0x8000000000000000

test_ndr_write_string_empty
  - Write empty string, read back
  - Verify alignment padding correct

test_ndr_write_string_odd_length
  - Write "abc" (3 chars + NUL = 4 bytes, ALIGN(4,2) = 4)
  - Verify offset correctly aligned

test_ndr_write_bytes_zero_length
  - Write 0 bytes
  - Verify no crash

test_ndr_read_past_end
  - Set offset near end, try to read int32
  - Verify returns -EINVAL
```

---

### ksmbd_test_unicode.c Enhancements

#### smb_from_utf16 conversion
```
test_smb_from_utf16_ascii
  - UTF-16LE "Hello" to utf8
  - Verify output == "Hello\0"

test_smb_from_utf16_bmp
  - UTF-16LE with BMP chars (e-acute, n-tilde)
  - Verify correct UTF-8 encoding

test_smb_from_utf16_empty
  - UTF-16LE with just null terminator
  - Verify output == "\0"

test_smb_from_utf16_tolen_boundary
  - Output buffer exactly fits the string
  - Verify no buffer overrun

test_smb_from_utf16_tolen_too_small
  - Output buffer smaller than needed
  - Verify truncation without crash
```

#### Surrogate pair handling
```
test_smb_from_utf16_surrogate_pair
  - UTF-16LE surrogate pair for U+10000 (LINEAR B SYLLABLE B008 A)
  - Verify correct 4-byte UTF-8 output

test_smbConvertToUTF16_supplementary
  - UTF-8 4-byte char (U+10000) to UTF-16LE
  - Verify surrogate pair in output

test_smbConvertToUTF16_ivs
  - UTF-8 IVS sequence (base + VS, 7-8 bytes)
  - Verify correct multi-unit UTF-16 output
```

#### smb_strtoUTF16 tests
```
test_smb_strtoUTF16_ascii
  - "test" to UTF-16LE
  - Verify 4 code units + null

test_smb_strtoUTF16_utf8_input
  - "caf\xc3\xa9" (cafe with accent)
  - Verify correct UTF-16LE output

test_smb_strtoUTF16_empty
  - Empty string
  - Verify 0 code units, null terminator present

test_smb_strtoUTF16_max_len
  - String of exactly len bytes
  - Verify output capped at len code units
```

#### smbConvertToUTF16 mapchars
```
test_smbConvertToUTF16_mapchars_colon
  - ':' maps to UNI_COLON (0xF003)

test_smbConvertToUTF16_mapchars_asterisk
  - '*' maps to UNI_ASTERISK

test_smbConvertToUTF16_mapchars_question
  - '?' maps to UNI_QUESTION

test_smbConvertToUTF16_mapchars_pipe
  - '|' maps to UNI_PIPE

test_smbConvertToUTF16_mapchars_angle_brackets
  - '<' maps to UNI_LESSTHAN, '>' to UNI_GRTRTHAN

test_smbConvertToUTF16_no_mapchars
  - mapchars=0 delegates to smb_strtoUTF16
```

#### smb_strndup_from_utf16
```
test_strndup_from_utf16_unicode
  - UTF-16LE "Test", is_unicode=true
  - Verify output == "Test"

test_strndup_from_utf16_ascii
  - ASCII "Test", is_unicode=false
  - Verify output == "Test"

test_strndup_from_utf16_oom
  - (Hard to test) Verify returns ERR_PTR(-ENOMEM)
```

#### Overlong UTF-8 sequences
```
test_is_char_allowed_overlong_null
  - 2-byte overlong encoding of NUL (0xC0 0x80)
  - Verify high-bit-set path allows it (is_char_allowed only checks ASCII)

test_smbConvertToUTF16_overlong
  - Overlong UTF-8 sequence as input
  - Verify '?' substitution (unknown char path)
```

#### Null bytes in middle of string
```
test_smb1_utf16_name_length_embedded_null
  - UTF-16LE with null in the middle: 'A', 0, 'B'
  - Verify length stops at first null

test_smb_from_utf16_embedded_null
  - Verify conversion stops at first null code unit
```

---

### ksmbd_test_asn1.c (NEW)

Tests for ASN.1/SPNEGO token parsing and construction.

#### asn1_subid_decode
```
test_asn1_subid_decode_single_byte
  - Byte 0x06 (no continuation bit)
  - Verify *subid == 6

test_asn1_subid_decode_multi_byte
  - Bytes 0x86 0x48 (continuation encoding for 840)
  - Verify *subid == 840

test_asn1_subid_decode_overflow
  - Bytes that would overflow unsigned long
  - Verify returns false

test_asn1_subid_decode_empty
  - begin == end
  - Verify returns false
```

#### asn1_oid_decode
```
test_asn1_oid_decode_spnego
  - Encoded SPNEGO OID (1.3.6.1.5.5.2)
  - Verify decoded OID matches SPNEGO_OID

test_asn1_oid_decode_ntlmssp
  - Encoded NTLMSSP OID
  - Verify decoded OID matches NTLMSSP_OID

test_asn1_oid_decode_krb5
  - Encoded KRB5 OID
  - Verify decoded OID matches KRB5_OID

test_asn1_oid_decode_empty
  - vlen == 0
  - Verify returns false

test_asn1_oid_decode_single_byte
  - vlen == 1, value encodes OID with 2 arcs
  - Verify correct first/second arc split

test_asn1_oid_decode_too_large
  - vlen > UINT_MAX / sizeof(unsigned long)
  - Verify returns false (allocation guard)
```

#### oid_eq
```
test_oid_eq_same
  - Two identical OIDs
  - Verify returns true

test_oid_eq_different_length
  - OIDs with different lengths
  - Verify returns false

test_oid_eq_same_length_different_values
  - Same length but different arc values
  - Verify returns false
```

#### compute_asn_hdr_len_bytes
```
test_asn_hdr_len_short_form
  - length <= 0x7F
  - Verify returns 0

test_asn_hdr_len_1byte
  - length 0x80..0xFF
  - Verify returns 1

test_asn_hdr_len_2byte
  - length 0x100..0xFFFF
  - Verify returns 2

test_asn_hdr_len_3byte
  - length 0x10000..0xFFFFFF
  - Verify returns 3

test_asn_hdr_len_4byte
  - length > 0xFFFFFF
  - Verify returns 4
```

#### encode_asn_tag
```
test_encode_asn_tag_short_length
  - Small payload length
  - Verify correct tag/seq/length encoding

test_encode_asn_tag_long_length
  - Large payload length (> 0x7F)
  - Verify multi-byte length encoding

test_encode_asn_tag_buffer_overflow
  - bufsize too small for the encoding
  - Verify returns -EINVAL
```

#### SPNEGO blob construction
```
test_build_spnego_ntlmssp_neg_blob
  - Build with known ntlm_blob
  - Verify total_len calculation
  - Verify ASN.1 structure parseable

test_build_spnego_ntlmssp_neg_blob_empty_ntlm
  - ntlm_blob_len == 0
  - Verify valid structure

test_build_spnego_ntlmssp_neg_blob_max_size
  - ntlm_blob_len near U16_MAX
  - Verify bounds checking

test_build_spnego_ntlmssp_neg_blob_negative_len
  - ntlm_blob_len < 0
  - Verify returns -EINVAL

test_build_spnego_ntlmssp_auth_blob_accept
  - neg_result == 0
  - Verify buf[ofs] == 0

test_build_spnego_ntlmssp_auth_blob_reject
  - neg_result != 0
  - Verify buf[ofs] == 2
```

#### SPNEGO token parsing (integration)
```
test_ksmbd_gssapi_this_mech_valid
  - Valid SPNEGO OID
  - Verify returns 0

test_ksmbd_gssapi_this_mech_invalid
  - Non-SPNEGO OID
  - Verify returns -EBADMSG

test_ksmbd_neg_token_init_mech_type_ntlmssp
  - NTLMSSP OID in value
  - Verify conn->auth_mechs includes KSMBD_AUTH_NTLMSSP

test_ksmbd_neg_token_init_mech_type_krb5
  - KRB5 OID in value
  - Verify conn->auth_mechs includes KSMBD_AUTH_KRB5

test_ksmbd_neg_token_init_mech_type_mskrb5
  - MSKRB5 OID in value
  - Verify conn->auth_mechs includes KSMBD_AUTH_MSKRB5

test_ksmbd_neg_token_init_mech_type_unknown
  - Unknown OID
  - Verify returns -EBADMSG

test_ksmbd_neg_token_init_mech_token_alloc
  - Valid mechToken value
  - Verify conn->mechToken allocated and copied
  - Verify conn->mechTokenLen == vlen

test_ksmbd_neg_token_init_mech_token_empty
  - vlen == 0
  - Verify returns -EINVAL

test_ksmbd_neg_token_init_mech_token_replaces_previous
  - Call twice with different tokens
  - Verify second token replaces first (and first freed)
```

---

## Compression-specific Tests

### Round-trip Matrix

Each algorithm must be tested with these input classes:

| Input class | Size | Description |
|-------------|------|-------------|
| Empty | 0 bytes | Edge case: no data |
| Single byte | 1 byte | Minimum meaningful input |
| Small | 16 bytes | Below any windowing threshold |
| Medium | 4096 bytes | Single LZNT1 chunk boundary |
| Large | 65536 bytes | Multiple chunks/blocks |
| Very large | 1048576 bytes | 1MB stress test |
| All zeros | 4096 bytes | Maximum compressibility |
| All 0xFF | 4096 bytes | Maximum compressibility, different pattern |
| Random | 4096 bytes | Minimum compressibility |
| Repeated 16-byte pattern | 4096 bytes | Good compressibility |
| Alternating bytes | 4096 bytes | Moderate compressibility |
| Mostly zero with spikes | 4096 bytes | Mixed compressibility |
| Ascending bytes 0..255 loop | 4096 bytes | Structured but varied |

### Malformed Compressed Data (security tests)

```
test_decompress_zero_length_input
  - All algorithms: src_len = 0
  - Verify returns error or 0

test_decompress_one_byte_input
  - All algorithms: src_len = 1 (too small for any header)
  - Verify returns error

test_decompress_huge_claimed_original_size
  - OriginalCompressedSegmentSize = 0xFFFFFFFF
  - Verify allocation guard prevents multi-GB allocation

test_decompress_output_size_mismatch
  - Compressed data claims 4096 bytes but decompresses to 8192
  - Verify excess detected and rejected

test_decompress_lznt1_invalid_chunk_signature
  - LZNT1 chunk with bit 15 set but bad size
  - Verify returns error

test_decompress_lz77_invalid_match_distance
  - LZ77 match with distance > current position
  - Verify returns error

test_decompress_lz77huff_bad_huffman_tree
  - Invalid code length table
  - Verify returns error (not infinite loop)
```

### Compression Bomb Detection

```
test_compress_bomb_lznt1
  - 100 bytes that decompress to 100MB
  - Verify decompression rejects or limits output

test_compress_bomb_lz77
  - Small LZ77 compressed blob that expands enormously
  - Verify output size check

test_compress_bomb_lz77huff
  - Small Huffman compressed blob that expands enormously
  - Verify output size check
```

### Boundary Sizes

```
test_compress_at_max_stream_prot_len
  - Input exactly MAX_STREAM_PROT_LEN (0x00FFFFFF)
  - Verify compression handles gracefully

test_compress_at_max_write_size
  - Input at smb2_max_write_size boundary
  - Verify no overflow in size calculations
```

---

## QUIC-specific Tests

### RFC 9000 Compliance Edge Cases

```
test_quic_initial_salt_v1
  - Verify initial salt matches RFC 9001 Section 5.2

test_quic_retry_integrity_tag
  - If retry support added, verify Retry Integrity Tag computation

test_quic_connection_id_validation
  - DCID length 0 (valid for short header)
  - DCID length 20 (maximum per RFC 9000)
  - DCID length 21 (invalid, must reject)

test_quic_stream_frame_parsing
  - Parse STREAM frame with all flag combinations (OFF/LEN/FIN)

test_quic_padding_frame
  - Verify padding frames (type 0x00) are silently consumed

test_quic_ack_frame_construction
  - Verify ACK frame correctly encodes acknowledged ranges

test_quic_connection_close_frame
  - Verify CONNECTION_CLOSE with error code encodes correctly
  - Verify reason phrase handling

test_quic_max_packet_size
  - UDP datagram at 1200 bytes (minimum for QUIC Initial)
  - UDP datagram at 65535 bytes (IP maximum)
```

### RFC 9001 Compliance (QUIC-TLS)

```
test_quic_initial_key_derivation_appendix_a
  - Full RFC 9001 Appendix A test vectors
  - Verify client_in, server_in secrets
  - Verify key, iv, hp values for both client and server

test_quic_packet_protection_roundtrip
  - Protect then unprotect Initial packet
  - Verify payload matches original

test_quic_key_update
  - Derive new keys from previous keys
  - Verify independent of packet number
```

### SMB over QUIC specifics (MS-SMB2 Appendix C)

```
test_quic_no_rfc1002_prefix
  - Verify SMB messages on QUIC do NOT have 4-byte NetBIOS header

test_quic_stream_id_zero
  - Verify all SMB traffic uses bidirectional stream 0

test_quic_port_443
  - Verify default listener port is 443
```

---

## Fuzz Targets

New fuzz harnesses for integration into syzbot or custom kernel fuzzing:

### Compression fuzzer
```
fuzz_lznt1_decompress
  - Feed random bytes to ksmbd_lznt1_decompress()
  - Target: buffer overflows, infinite loops, OOM

fuzz_lz77_decompress
  - Feed random bytes to ksmbd_lz77_decompress()
  - Target: invalid match references, output overflow

fuzz_lz77huff_decompress
  - Feed random bytes to ksmbd_lz77huff_decompress()
  - Target: invalid Huffman tables, bitstream overruns

fuzz_pattern_v1_decompress
  - Feed random bytes to smb2_pattern_v1_decompress()
  - Target: size field manipulation

fuzz_smb2_decompress_req
  - Feed random SMB2_COMPRESSION_TRANSFORM buffers
  - Target: header parsing, algorithm dispatch, chained decompression
```

### QUIC packet fuzzer
```
fuzz_quic_parse_initial_packet
  - Feed random UDP datagrams
  - Target: header parsing, length validation

fuzz_quic_parse_crypto_frames
  - Feed random QUIC payload bytes
  - Target: frame type parsing, varint decoding

fuzz_quic_varint_decode
  - Feed random 1-8 byte sequences
  - Target: overflow, truncation
```

### IPC message fuzzer
```
fuzz_ipc_validate_msg
  - Feed random payloads with known type codes
  - Target: size calculation overflows

fuzz_handle_response
  - Feed random payloads with varying sizes
  - Target: handle lookup, size validation
```

### ASN.1/SPNEGO fuzzer
```
fuzz_ksmbd_decode_negTokenInit
  - Feed random BER-encoded blobs
  - Target: OID decoding, allocation, tag parsing

fuzz_asn1_oid_decode
  - Feed random byte sequences as OID values
  - Target: subid overflow, allocation size

fuzz_build_spnego_ntlmssp_neg_blob
  - Feed random ntlm_blob_len values with random blobs
  - Target: length calculation overflow, buffer bounds
```

### NDR fuzzer
```
fuzz_ndr_decode_dos_attr
  - Feed random NDR-encoded buffers
  - Target: version parsing, field reading, truncation

fuzz_ndr_decode_v4_ntacl
  - Feed random NDR-encoded NT ACL buffers
  - Target: version check, desc validation, sd_buf allocation
```

---

## Test Priority and Implementation Order

### Phase 1 (Critical - implement immediately)
1. `ksmbd_test_compress.c` - All round-trip tests for all algorithms
2. `ksmbd_test_asn1.c` - SPNEGO parsing, OID decoding
3. `ksmbd_test_ndr.c` enhancements - NT ACL and POSIX ACL

### Phase 2 (High - implement before next release)
4. `ksmbd_test_connection.c` - State machine, refcount, per-IP limits
5. `ksmbd_test_work.c` - IOV pinning, allocation
6. `ksmbd_test_unicode.c` enhancements - Full conversion paths

### Phase 3 (Medium - implement for full coverage)
7. `ksmbd_test_transport_tcp.c` - kvec_array_init, interface management
8. `ksmbd_test_transport_ipc.c` - Message validation
9. `ksmbd_test_conn_hash.c` enhancements - Concurrency, counters
10. `ksmbd_test_server.c` - Configuration, dispatch

### Phase 4 (Advanced - requires QUIC infrastructure)
11. `ksmbd_test_transport_quic.c` - HKDF, AEAD, varint, state machine
12. Fuzz targets for all parsers

---

## Test Infrastructure Notes

### KUnit constraints
- Tests must not link directly to ksmbd module symbols (unless loaded)
- Pure-logic tests replicate the algorithm inline (like existing tests)
- Tests needing full module initialization require loadable module test harness

### Compression test helpers needed
- `smb2_compress_data` and `smb2_decompress_data` are static; need either:
  - Wrapper exports (`EXPORT_SYMBOL_GPL` for test module)
  - OR replicated algorithm code in test file
  - OR `#include "../src/core/smb2_compress.c"` in test file (fragile)
- Recommended: add `CONFIG_KSMBD_KUNIT_TEST` wrappers that export the
  compress/decompress functions only when tests are enabled

### QUIC test helpers needed
- Varint encode/decode and HKDF are good candidates for direct unit testing
- AEAD tests need kernel crypto API available
- Consider test module that loads crypto transforms for QUIC key derivation

### Mock objects needed
- `struct ksmbd_conn` stub (for ASN.1 parser tests)
- `struct ksmbd_work` stub (for compression and work tests)
- `struct socket` mock (for TCP transport tests, if not using replicated logic)
- NLS table stub or load_nls("utf8") (for unicode tests)

---

## Total Test Count Summary

| Test File | Existing | New/Enhanced | Total |
|-----------|----------|-------------|-------|
| ksmbd_test_conn_hash.c | 10 | 9 | 19 |
| ksmbd_test_ndr.c | 5 | 16 | 21 |
| ksmbd_test_unicode.c | 19 | 24 | 43 |
| ksmbd_test_connection.c (NEW) | 0 | 25 | 25 |
| ksmbd_test_transport_tcp.c (NEW) | 0 | 17 | 17 |
| ksmbd_test_transport_ipc.c (NEW) | 0 | 15 | 15 |
| ksmbd_test_transport_quic.c (NEW) | 0 | 32 | 32 |
| ksmbd_test_compress.c (NEW) | 0 | 60+ | 60+ |
| ksmbd_test_work.c (NEW) | 0 | 13 | 13 |
| ksmbd_test_server.c (NEW) | 0 | 16 | 16 |
| ksmbd_test_asn1.c (NEW) | 0 | 30 | 30 |
| Fuzz targets | 0 | 14 | 14 |
| **TOTAL** | **34** | **271+** | **305+** |
