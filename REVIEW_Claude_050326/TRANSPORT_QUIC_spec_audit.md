# Transport Quic Spec Audit

Agent ID: a782db7382b1d1f0e

Now I have all the information needed for the complete audit. Let me compile the results.

---

Here is the complete audit of all five test files against the MS-SMB2 protocol specification (`/home/ezechiel203/ksmbd/ms-smb2.txt`).

## Summary

| File | Tests | CORRECT | WRONG | QUESTIONABLE |
|------|-------|---------|-------|--------------|
| `test/ksmbd_test_transport.c` | 20 | 20 | 0 | 0 |
| `test/ksmbd_test_quic.c` | 47 | 46 | 0 | 1 |
| `test/ksmbd_test_connection.c` | 33 | 33 | 0 | 0 |
| `test/ksmbd_test_tcp_shutdown.c` | 26 | 26 | 0 | 0 |
| `test/ksmbd_test_rdma.c` | 24 | 24 | 0 | 0 |
| **Total** | **150** | **149** | **0** | **1** |

## Detailed Analysis

### 1. `/home/ezechiel203/ksmbd/test/ksmbd_test_transport.c` (20 tests)

**All 20 tests: CORRECT**

These tests exercise `kvec_array_init()` (a transport-level scatter/gather buffer management helper), interface allocation, and connection counting logic. None of these tests make claims about the MS-SMB2 protocol wire format or protocol semantics. They are purely testing internal kernel implementation helpers:

- **kvec_array_init tests (14 tests)**: Test scatter/gather vector partial-consumption arithmetic. These are pure data structure tests with no protocol-level assertions.
- **Interface management tests (3 tests)**: Test allocation/deallocation of interface descriptors and list search. Implementation-specific, no spec claims.
- **Connection counting tests (3 tests)**: Test `atomic_t` increment/decrement for active connection counts. The max-connections limit logic is implementation-specific and not specified by MS-SMB2.

### 2. `/home/ezechiel203/ksmbd/test/ksmbd_test_quic.c` (47 tests)

**46 tests: CORRECT, 1 test: QUESTIONABLE**

**Varint encoding/decoding tests (13 tests)**: All boundary values (63/64, 16383/16384, 1073741823/1073741824) and the maximum value (2^62 - 1 = 4611686018427387903) match RFC 9000 Section 16 exactly. The overflow check at 2^62 returning `-ERANGE` is correct. All CORRECT.

**State machine tests (4 tests)**: The QUIC state machine (INITIAL -> HANDSHAKE -> CONNECTED -> CLOSING) is implementation-specific. The transitions tested are reasonable and consistent with RFC 9000 Section 17.2 long header packet types. All CORRECT.

**DCID hash tests (2 replicated + 5 real)**: Hash function tests are implementation-specific. The max DCID length of 20 bytes matches RFC 9000 Section 17.2 ("the length of the DCID field... is limited to 20 bytes"). All CORRECT.

**Initial packet parsing tests (4 replicated + 9 real)**: The long header form bit (0x80), version field position, DCID length field position, and SCID length field position all match RFC 9000 Section 17.2. The max DCID length check of 20 bytes is correct per RFC 9000. Short header rejection and Handshake type rejection for an Initial-only parser are correct. All CORRECT.

**CRYPTO frame parsing tests (3 tests)**: Frame type 0x06 for CRYPTO frames matches RFC 9000 Section 19.6. The offset and length varint fields are correct. All CORRECT.

**Version negotiation tests (1 test)**: QUIC_VERSION_1 = 0x00000001 matches RFC 9000 Section 15. QUIC_VERSION_2 = 0x6B3343CF matches RFC 9369 Section 2. CORRECT.

**Connection ID validation tests (3 tests)**: Zero-length DCID is valid (RFC 9000 Section 17.3.1 allows zero-length CIDs in short headers), max length 20 is correct (RFC 9000 Section 17.2), 21 is invalid. All CORRECT.

**AEAD nonce construction test (1 test)**: XOR of packet number into the last 8 bytes of the 12-byte base IV matches RFC 9001 Section 5.3. CORRECT.

**SMB over QUIC tests (2 tests)**:
- `test_quic_no_rfc1002_prefix`: **QUESTIONABLE**. The test asserts that SMB over QUIC does NOT use a 4-byte prefix header. The MS-SMB2 spec section 2.1 defines the "Direct TCP transport packet header" (4 bytes: zero byte + 3-byte length) only for "Direct TCP" transport. QUIC is listed as a separate transport where "All SMB2 messages are encapsulated inside QUIC protocol" (section 4.10). The spec does not explicitly state whether the Direct TCP header is used or not used on QUIC. However, the test's comment incorrectly calls this the "RFC1002 header" -- RFC1002 is NetBIOS, not Direct TCP. The Direct TCP header is a different framing mechanism. While the test's conclusion is almost certainly correct (QUIC streams provide their own framing, making the Direct TCP header unnecessary), the spec is not entirely explicit about this, making it **QUESTIONABLE** rather than definitively CORRECT or WRONG. The closest spec reference: MS-SMB2 section 2.1.
- `test_quic_default_port_443`: Port 443 for QUIC matches MS-SMB2 section 1.8 ("QUIC over UDP port 443"). CORRECT.

**Connection hash insert/remove test (1 test)**: Implementation-specific. CORRECT.

**Header protection tests (2 tests)**: Long header masking of 4 bottom bits and short header masking of 5 bottom bits match RFC 9001 Section 5.4.1. The XOR roundtrip property is mathematically inherent. All CORRECT.

### 3. `/home/ezechiel203/ksmbd/test/ksmbd_test_connection.c` (33 tests)

**All 33 tests: CORRECT**

**Allocation tests (3 tests)**: Verify initial state of ksmbd_conn struct fields. The initial value `total_credits = 1` matches the MS-SMB2 spec section 3.3.4.1 which specifies the server initializes `Connection.CommandSequenceWindow` with "a starting receive sequence of 0 and a window size of 1" (section 3.3.4.1, referenced from section 19592). CORRECT.

**State machine tests (7 tests)**: The connection states (NEW, GOOD, NEED_NEGOTIATE, NEED_SETUP, NEED_RECONNECT, EXITING, RELEASING) are implementation-specific to ksmbd. The MS-SMB2 spec does not define specific state names for connections but the transitions are consistent with the protocol lifecycle (negotiate -> session setup -> tree connect -> normal operation -> disconnect). All CORRECT as implementation-specific tests.

**Refcount tests (3 tests)**: Pure implementation tests of refcount_t behavior. No spec relevance. CORRECT.

**Request running counter tests (2 tests)**: Implementation-specific request tracking. CORRECT.

**r_count tests (2 tests)**: Implementation-specific reader-count tracking. CORRECT.

**Hash table tests (5 tests)**: Test the global connection hash table used for dialect validation (FSCTL_VALIDATE_NEGOTIATE_INFO, MS-SMB2 section 3.3.5.15.12). The hash operations are implementation-specific but the concept of maintaining a connection registry is consistent with the spec. CORRECT.

**Dialect lookup tests (2 tests)**: `ksmbd_conn_lookup_dialect` searches for connections with matching ClientGUID, which implements the server-side validation required by MS-SMB2 section 3.3.5.15.12 (Validate Negotiate Info). CORRECT.

**Credit management tests (2 tests)**: The initial credit of 1 matches MS-SMB2 section 3.3.4.1/19592 (window size of 1). Credit arithmetic is straightforward addition/subtraction. CORRECT.

**need_neg flag tests (2 tests)**: Implementation-specific negotiate-needed flag. CORRECT.

**Cancel behavior test (1 test)**: The test verifies CANCEL requests increment req_running but don't add to the requests list. This is consistent with MS-SMB2 section 3.3.5.16 which says CANCEL is processed immediately and is not queued. CORRECT.

**Outstanding async test (1 test)**: Implementation-specific async counter. CORRECT.

**Server configuration tests (7 tests)**: Test server config helpers (netbios name, server string, work group). These are ksmbd-specific. The `ksmbd_server_running()` and `ksmbd_server_configurable()` helpers test server states that are implementation-specific. All CORRECT.

### 4. `/home/ezechiel203/ksmbd/test/ksmbd_test_tcp_shutdown.c` (26 tests)

**All 26 tests: CORRECT**

All tests in this file exercise implementation-specific TCP transport shutdown logic:

**Shutdown flag tests (3 tests)**: Test the shutting_down atomic flag and its irreversibility. These are internal implementation details of ksmbd's TCP transport layer. No MS-SMB2 spec claims. CORRECT.

**Interface list tests (3 tests)**: Test linked-list management of network interfaces. Implementation-specific. CORRECT.

**Refcount tests (5 tests)**: Test reference counting for interface lifecycle management. Implementation-specific. CORRECT.

**Shutdown sequence tests (3 tests)**: Test ordering guarantees (flag set before socket close, recv returns -ESHUTDOWN when flag is set, kthread exits on shutdown). These verify implementation correctness without making protocol-level claims. CORRECT.

**Multiple interface tests (1 test)**: Verifies that shutting down one interface does not affect others. Implementation-specific. CORRECT.

**Idempotency/edge case tests (6 tests)**: Test double-shutdown safety, null safety, SO_REUSEADDR. Implementation-specific. CORRECT.

**Completion synchronization tests (2 tests)**: Test kernel completion mechanism for kthread synchronization. Implementation-specific. CORRECT.

**State machine tests (2 tests)**: Test interface states (DOWN, CONFIGURED). Implementation-specific. CORRECT.

**Mutex protection tests (2 tests)**: Test that interface list operations are protected by mutex. Implementation-specific. CORRECT.

### 5. `/home/ezechiel203/ksmbd/test/ksmbd_test_rdma.c` (24 tests)

**All 24 tests: CORRECT**

**I/O size constants (4 tests)**: Verify `SMBD_DEFAULT_IOSIZE` = 8MB, `SMBD_MIN_IOSIZE` = 512KB, `SMBD_MAX_IOSIZE` = 16MB, and that min <= default <= max. These match the values defined in `transport_rdma.h` and are consistent with [MS-SMBD] implementation guidance. CORRECT.

**SMB Direct negotiate values (7 tests)**: 
- Version 0x0100 matches [MS-SMBD] section 2.2.1/3.1.5.2 (only version 0x0100 is defined).
- Default max_send_size = 1364 and max_receive_size = 1364 are the implementation's chosen defaults, consistent with [MS-SMBD] guidance.
- Max fragmented receive size = 1MB is a reasonable default.
- Credit values of 255 are implementation defaults within the __le16 range.
All CORRECT.

**Buffer management tests (2 tests)**: Verify that the data transfer header doesn't consume the entire send buffer, and that credit max fits in __le16. CORRECT.

**Connection lifecycle and structure tests (5 tests)**:
- Port 445 for InfiniBand and 5445 for iWARP match [MS-SMBD] section 2.1 standards assignments.
- `smb_direct_negotiate_req` = 20 bytes, `smb_direct_negotiate_resp` = 32 bytes, `smb_direct_data_transfer` = 24 bytes. I verified these sizes against the actual struct definitions in `/home/ezechiel203/ksmbd/src/include/transport/transport_rdma.h` and they match exactly.
- Field offset tests for all three structures match the actual struct layouts and [MS-SMBD] wire format specifications (sections 2.2.1, 2.2.2, 2.2.3).
All CORRECT.

**Error/boundary tests (6 tests)**:
- I/O size boundary validation is implementation-specific. CORRECT.
- Zero-credit rejection and credit range validation (__le16 maximum) are consistent with [MS-SMBD]. CORRECT.
- `SMB_DIRECT_RESPONSE_REQUESTED` = 0x0001 matches [MS-SMBD] section 2.2.3. CORRECT.
- CM parameters and negotiate timeout are implementation defaults. CORRECT.
- SGE limits are implementation-specific hardware constraints. CORRECT.

## QUESTIONABLE Finding Detail

### Q-1: `test_quic_no_rfc1002_prefix` in `ksmbd_test_quic.c` (line 527-537)

**Test code:**
```c
static void test_quic_no_rfc1002_prefix(struct kunit *test)
{
    bool quic_transport = true;
    int rfc1002_size = quic_transport ? 0 : 4;
    KUNIT_EXPECT_EQ(test, rfc1002_size, 0);
}
```

**Issue:** The test comment says "SMB over QUIC does NOT use the 4-byte NetBIOS (RFC1002) header." This conflates two different framing mechanisms:
1. The RFC1002/NetBIOS framing (used on port 139)
2. The Direct TCP transport packet header (4-byte: zero byte + 3-byte length, used on port 445)

The MS-SMB2 spec section 2.1 defines the "Direct TCP transport packet header" for Direct TCP only, and lists QUIC as a separate transport. The spec does not explicitly state whether any framing header is used on QUIC. Since QUIC provides its own stream-level framing (RFC 9000 STREAM frames), it is reasonable to conclude no additional framing header is needed, but the MS-SMB2 spec is not explicit about this.

**Spec reference:** MS-SMB2 section 2.1 (Transport), section 4.10 (Negotiating Transport Level Encryption over QUIC).

**Verdict:** The test expectation is almost certainly correct in practice, but the comment misidentifies the header type, and the spec is not explicit about QUIC framing, making this QUESTIONABLE.

## Final Counts

- **Total tests audited: 150**
- **CORRECT: 149**
- **WRONG: 0**
- **QUESTIONABLE: 1**

Sources:
- [RFC 9369 - QUIC Version 2](https://datatracker.ietf.org/doc/html/rfc9369)