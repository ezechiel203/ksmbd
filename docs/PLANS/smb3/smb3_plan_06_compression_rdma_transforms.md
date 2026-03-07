# SMB3 Plan 06: Compression and RDMA Transforms

**Audit date:** 2026-03-01
**Spec references:** MS-SMB2 §2.2.42, §2.2.42.1, §2.2.42.2, §2.2.42.2.3, §2.2.43, §2.2.3.1.3, §3.3.5.4, MS-XCA §2.3

---

## Compression Transform Header

### Header Structure (MS-SMB2 §2.2.42)

The compression transform header is defined at
`/home/ezechiel203/ksmbd/src/include/protocol/smb2pdu.h` lines 328–342:

```c
/* SMB2 Compression Transform Header (MS-SMB2 2.2.42) */
struct smb2_compression_transform_hdr {
    __le32 ProtocolId;        /* 0xFC534D42 */
    __le32 OriginalCompressedSegmentSize;
    __le16 CompressionAlgorithm;
    __le16 Flags;
    __le32 Offset;
} __packed;

/* Chained compression payload header (MS-SMB2 2.2.42.1) */
struct smb2_compression_chained_payload_hdr {
    __le16 CompressionAlgorithm;
    __le16 Flags;
    __le32 Length;
} __packed;

#define SMB2_COMPRESSION_FLAG_NONE    0x0000
#define SMB2_COMPRESSION_FLAG_CHAINED 0x0001
#define SMB2_COMPRESSION_THRESHOLD    1024
```

**Findings:**

1. **ProtocolId verification (receive path):** `smb2_is_compression_transform_hdr()`
   (`smb2_compress.c:280`) verifies `hdr->ProtocolId == SMB2_COMPRESSION_TRANSFORM_ID`,
   which is `cpu_to_le32(0x424d53fc)` (`smb2pdu.h:117`). The comparison is correct:
   `SMB2_COMPRESSION_TRANSFORM_ID` is already in little-endian (via `cpu_to_le32`), and
   `ProtocolId` is `__le32`, so the comparison is type-safe. PASS.

2. **ProtocolId on send path:** `smb2_compress_resp()` (`smb2_compress.c:587`) sets
   `comp_hdr->ProtocolId = SMB2_COMPRESSION_TRANSFORM_ID` directly. Correct. PASS.

3. **Comment vs. wire value discrepancy:** The struct comment says `/* 0xFC534D42 */` but
   the actual wire value is `0xFC 'S' 'M' 'B'`, which in little-endian memory order
   reads as bytes `[FC, 53, 4D, 42]`. The constant `cpu_to_le32(0x424d53fc)` encodes
   this as `le32` so on a little-endian host the bytes are `[FC, 53, 4D, 42]`. This
   matches the spec. The comment notation `0xFC534D42` is accurate for the big-endian
   numeric value. No bug.

4. **OriginalCompressedSegmentSize validation:** `smb2_decompress_req()` (`smb2_compress.c:
   326–347`) extracts `original_size` and caps it at `min(2MB, conn->vals->max_write_size)`.
   PARTIAL - see Security Analysis section for the 2 MB hardcoded cap issue.

5. **Flags field:** Both `SMB2_COMPRESSION_FLAG_NONE (0x0000)` and
   `SMB2_COMPRESSION_FLAG_CHAINED (0x0001)` are defined (`smb2pdu.h:344–345`). Chained
   flag is checked on receive (`smb2_compress.c:320`) and rejected with `-EOPNOTSUPP`.
   The send path always uses `SMB2_COMPRESSION_FLAG_NONE` (`smb2_compress.c:590`). PARTIAL.

6. **Offset field semantics:** The code correctly treats the `Offset` field as the number
   of uncompressed bytes immediately following the transform header before the compressed
   region (`smb2_compress.c:389–391`). This matches MS-SMB2 §2.2.42 for non-chained.
   On the response side, the SMB2 header is used as the uncompressed prefix with
   `Offset = sizeof(struct smb2_hdr)` (`smb2_compress.c:591`). PASS.

7. **Minimum message size gate:** `ksmbd_smb_request()` (`protocol/common/smb_common.c:
   204–209`) checks that compression was negotiated before accepting compressed requests.
   If `conn->compress_algorithm == SMB3_COMPRESS_NONE`, a compressed request is rejected.
   PASS.

---

## Compression Algorithm Implementations

### Algorithm Constants

Defined at `smb2pdu.h:311–316`:

| Value  | Constant               | MS-SMB2 ID |
|--------|------------------------|------------|
| 0x0000 | `SMB3_COMPRESS_NONE`   | NONE       |
| 0x0001 | `SMB3_COMPRESS_LZNT1`  | LZNT1      |
| 0x0002 | `SMB3_COMPRESS_LZ77`   | LZ77       |
| 0x0003 | `SMB3_COMPRESS_LZ77_HUFF` | LZ77+Huffman |
| 0x0004 | `SMB3_COMPRESS_PATTERN_V1` | Pattern_V1 |
| 0x0005 | `SMB3_COMPRESS_LZ4`    | **NON-SPEC** |

**Critical issue:** LZ4 (`0x0005`) is NOT a valid algorithm in MS-SMB2. The spec defines
only NONE (0), LZNT1 (1), LZ77 (2), LZ77+Huffman (3), and Pattern_V1 (4). The value
`0x0005` is unassigned in all known spec revisions.

### Per-Algorithm Status

#### NONE (0x0000)
- Compress: Not applicable (passthrough).
- Decompress: Not applicable.
- Negotiate: `conn->compress_algorithm` is initialized to `SMB3_COMPRESS_NONE`
  (`smb2_negotiate.c:369`); it remains NONE if no mutual algorithm found.

#### LZNT1 (0x0001)
- Compress: **Stub** — `smb2_compress_data()` returns 0 (no compression)
  (`smb2_compress.c:235–238`). No kernel LZNT1 API exists in mainline Linux.
- Decompress: **Not implemented** — `smb2_decompress_data()` returns `-EOPNOTSUPP`
  (`smb2_compress.c:267–270`).
- Negotiate: Will be selected if client offers it but is not preferred; see
  `decode_compress_ctxt()` below.

#### LZ77 (0x0002)
- Compress: **Stub** — returns 0.
- Decompress: **Not implemented** — returns `-EOPNOTSUPP`.
- Negotiate: Same as LZNT1.

#### LZ77+Huffman (0x0003)
- Compress: **Stub** — returns 0.
- Decompress: **Not implemented** — returns `-EOPNOTSUPP`.
- Negotiate: Same as LZNT1.

#### Pattern_V1 (0x0004)
- Compress: **Implemented** at `smb2_compress.c:70–101`. Checks if the entire buffer is
  a single repeated byte, emits an 8-byte `pattern_v1_payload` struct.
- Decompress: **Implemented** at `smb2_compress.c:113–132`. Validates that
  `Repetitions == original_size`, then calls `memset()`.
- Kernel API: None — custom implementation, no kernel library used.

#### LZ4 (0x0005) — NON-SPEC EXTENSION
- Compress: **Implemented** at `smb2_compress.c:152–167` using `LZ4_compress_default()`
  from `<linux/lz4.h>`.
- Decompress: **Implemented** at `smb2_compress.c:179–201` using `LZ4_decompress_safe()`.
- Kernel API: `<linux/lz4.h>` — kernel's built-in LZ4 block API.
- **CRITICAL BUG:** `0x0005` is not assigned by MS-SMB2. A compliant Windows client
  will never advertise this value. This implementation is unreachable by any spec-compliant
  peer and will break interoperability if a client sends `0x0005` as a valid algorithm
  request, because the server will accept and use a non-spec algorithm.

### Negotiate Context Handling for Compression (MS-SMB2 §2.2.3.1.3)

`decode_compress_ctxt()` (`smb2_negotiate.c:362–419`):

1. Initializes `conn->compress_algorithm = SMB3_COMPRESS_NONE` (`smb2_negotiate.c:369`).
2. Validates `CompressionAlgorithmCount > 0` and returns `STATUS_INVALID_PARAMETER` if
   zero (`smb2_negotiate.c:379–382`). Compliant with spec requirement.
3. Validates array bounds with `check_mul_overflow()` (`smb2_negotiate.c:384–392`).
4. **Algorithm selection priority:** LZ4 first (non-spec), Pattern_V1 second. The three
   spec-mandated algorithms (LZNT1, LZ77, LZ77+Huffman) are never selected even if the
   client offers only those.
5. If no mutual algorithm is found, returns `STATUS_SUCCESS` with
   `conn->compress_algorithm = SMB3_COMPRESS_NONE`. This means compression is silently
   disabled, which is valid per spec (no mandatory compression).

**Duplicate context:** Detected and rejected (`smb2_negotiate.c:616–626`). PASS.

**Response context assembly:** `build_compress_ctxt()` (`smb2_negotiate.c:84–94`) builds
a response with `CompressionAlgorithmCount=1` and the negotiated algorithm. The `Flags`
field (chaining capability) is set to 0 (`smb2_negotiate.c:92`), advertising no chaining
support. Consistent with the runtime behavior that rejects chained requests.

---

## READ/WRITE Integration

### Compressed READ

The SMB2 READ handler is in `smb2_read_write.c`. A search for `SMB2_READFLAG_READ_COMPRESSED`
and `compress` in that file yields **no matches**. The server does not check the
`SMB2_READFLAG_READ_COMPRESSED` (0x00000002) flag in incoming READ requests.

The general response compression path (`smb2_compress_resp()` in `smb2_compress.c:469`)
is called from `server.c:418` for **all** responses when compression is negotiated —
but only for responses with `iov_cnt <= 2` (`smb2_compress.c:502–503`).

**READ response behavior:**
- For small reads (`< SMB2_COMPRESSION_THRESHOLD = 1024` bytes), compression is skipped
  (`smb2_compress.c:522–523`).
- For larger reads with `iov_cnt > 2` (SMB2 READ typically uses 3 iovs: RFC1002 header,
  SMB2 response header, and file data), compression is silently skipped (`smb2_compress.c:
  501–503`). This means **READ responses are never actually compressed in practice**
  because the read data is in `iov[2]`.
- The `SMB2_READFLAG_READ_COMPRESSED` flag is not honored at all.

### Compressed WRITE

`smb2_read_write.c:882`: The write handler checks `SMB2_WRITEFLAG_WRITE_THROUGH` but
does **not** handle any write compression flag. There is no
`SMB2_WRITEFLAG_WRITE_COMPRESSED` (note: the spec does not define a write compressed
flag as a WRITE request flag; compression is signalled via the compression transform
header wrapping the entire PDU rather than a flag inside the WRITE body).

**WRITE decompression path:** When a client sends a compressed WRITE, the
compression transform header wraps the entire SMB2 message. The decompression happens
at `server.c:229–233` via `smb2_decompress_req()` before the WRITE handler is called.
This is architecturally correct.

### Minimum Size Threshold

`SMB2_COMPRESSION_THRESHOLD = 1024` (`smb2pdu.h:348`). Responses smaller than 1024
bytes are not compressed (`smb2_compress.c:522–523`). MS-SMB2 does not mandate a
specific threshold, so this is an implementation choice.

---

## Chained Compression

### Specification Requirements (MS-SMB2 §2.2.42.2)

Chained compression allows a single transform to contain multiple independently
compressed segments, each preceded by an `SMB2_COMPRESSION_PAYLOAD_HEADER`. The
`Flags` field in the transform header is set to `SMB2_COMPRESSION_FLAG_CHAINED (0x0001)`.

### Implementation Status

- The struct `smb2_compression_chained_payload_hdr` is defined (`smb2pdu.h:338–342`).
- On receive: `smb2_decompress_req()` checks for the chained flag and immediately
  returns `-EOPNOTSUPP` (`smb2_compress.c:320–323`). No chained decompress logic.
- On send: The server always uses `SMB2_COMPRESSION_FLAG_NONE`. No chaining is
  implemented on the send path.
- The negotiate response sets `Flags=0` in `SMB2_COMPRESSION_CAPABILITIES`
  (`smb2_negotiate.c:92`), so clients are not told chaining is supported.

**Conclusion:** Chained compression is structurally declared (struct present) but fully
unimplemented at the protocol level. This is internally consistent — the negotiate
correctly advertises no chaining capability — but it means Pattern_V1 cannot be used
as specified. Per MS-SMB2, Pattern_V1 is designed specifically for use in chained mode
as a pre-scan pass before another compressor. Offering Pattern_V1 in non-chained mode
is a misuse of the algorithm (though the server currently accepts it in that context).

---

## RDMA Transform

### SMB2_RDMA_TRANSFORM_HEADER (MS-SMB2 §2.2.43)

**Specification:** The RDMA Transform header uses `ProtocolId = 0xFB534D42`. There is
no struct `smb2_rdma_transform_hdr` defined anywhere in the codebase. A search for
`0xFB534D42`, `FB534D42`, and `smb2_rdma_transform_hdr` in
`/home/ezechiel203/ksmbd/src` returns **no matches**.

The RDMA transform header as defined in MS-SMB2 §2.2.43 is used when actual RDMA
data is accompanied by a signing or encryption transform applied over the RDMA channel.
It is distinct from the `SMB2_TRANSFORM_HEADER` (`0xFD534D42`) used for encryption.

**Finding:** No RDMA Transform Header (`0xFB534D42`) implementation exists.

### RDMA Transform IDs

Defined at `smb2pdu.h:371–373`:
```c
#define SMB2_RDMA_TRANSFORM_NONE        cpu_to_le16(0x0000)
#define SMB2_RDMA_TRANSFORM_ENCRYPTION  cpu_to_le16(0x0001)
#define SMB2_RDMA_TRANSFORM_SIGNING     cpu_to_le16(0x0002)
```

These constants are correct per MS-SMB2 §2.2.43.

### Negotiate Context (SMB2_RDMA_TRANSFORM_CAPABILITIES, type 0x0007)

**Decode path:** `decode_rdma_transform_ctxt()` (`smb2_negotiate.c:501–542`):
- Validates structure size.
- Checks `TransformCount > 0` (silently returns on count=0, `smb2_negotiate.c:516–519`).
- Uses `check_mul_overflow()` for bounds safety.
- Accepts only known transform IDs: NONE, ENCRYPTION, SIGNING.
- Stores up to `ARRAY_SIZE(conn->rdma_transform_ids) = 3` values
  (`connection.h:126`).

**Build path:** `build_rdma_transform_ctxt()` (`smb2_negotiate.c:108–129`) echoes back
the stored transform IDs. This is correct for a server echoing its capabilities.

**Duplicate context:** Detected and rejected (`smb2_negotiate.c:644–647`). PASS.

### Actual RDMA Transform Application

`ksmbd_rdma_transform_supported()` (`transport_rdma.c:228–238`) is a query function
that checks if a given transform ID was negotiated. It is exported (`transport_rdma.h:68`)
but a search for callers in the codebase returns **no caller sites**. No code path
actually applies RDMA encryption or RDMA signing transforms to data.

**Transport-level RDMA path:** `smb_direct_rdma_read()` and `smb_direct_rdma_write()`
in `transport_rdma.c` perform raw RDMA read/write operations without any transform
application. The RDMA channel transmits data without encryption or signing transforms
even when they are negotiated.

---

## Security Analysis

### 1. Decompression Bomb / Amplification Attack

**Mitigation present:** `smb2_decompress_req()` (`smb2_compress.c:335–347`) caps
`original_size` at `min(2MB, conn->vals->max_write_size)`.

**Issue with 2 MB cap (P1):** The 2 MB hardcoded cap is not derived from the spec.
MS-SMB2 §2.2.42 requires that `OriginalCompressedSegmentSize` MUST NOT exceed
`MaxTransactSize` from the negotiate response. The server's `MaxTransactSize` is
`SMB3_DEFAULT_TRANS_SIZE = 1MB` (`smb2pdu.h:121`). Using `min(2MB, max_write_size)`
where `max_write_size` can be up to `SMB3_MAX_IOSIZE = 8MB` (`smb2pdu.h:123`) means
the cap is 2 MB, which is **double** the maximum legitimate `MaxTransactSize`. The
correct cap is `conn->vals->max_trans_size` (or the per-context maximum, whichever is
smaller).

**Amplification ratio check:** `smb2_compress.c:382–387` rejects messages where
`(original_size - offset) / compressed_len > 1024`. This is a useful secondary
defense but does not replace the size cap being tied to `MaxTransactSize`.

### 2. Pattern_V1 Decompress Safety

`smb2_pattern_v1_decompress()` (`smb2_compress.c:113–132`):
- Validates `src_len >= PATTERN_V1_COMPRESSED_SIZE` (8 bytes).
- Cross-checks `repetitions == original_size`. If these differ, returns `-EINVAL`.
- Checks `original_size > dst_len` before `memset()`.

No buffer overflow. The repetitions/original_size cross-check is tighter than strictly
required by the spec (which only says to fill `original_size` bytes), but it prevents
a client from claiming a larger expansion than declared. PASS.

### 3. LZ4 Decompress Safety

`smb2_lz4_decompress()` (`smb2_compress.c:179–201`):
- Calls `LZ4_decompress_safe(src, dst, src_len, original_size)`. The `original_size`
  parameter to `LZ4_decompress_safe` acts as the output buffer size limit; the kernel
  LZ4 implementation will not write beyond `original_size` bytes.
- After decompression, checks that the returned size equals `original_size`.
- No buffer overflow risk from the LZ4 call itself.

However, the `dst` buffer is allocated as `total_decompressed_len + 5` bytes
(`smb2_compress.c:413`), where `total_decompressed_len = original_size`. The `+5`
accounts for the RFC1002 4-byte header plus 1 alignment byte. LZ4 writes into
`decompressed_buf + 4 + offset`, so the maximum write is
`original_size - offset` bytes at that offset, staying within the allocated region.
PASS.

### 4. Compress Request Before Negotiation Gate

`ksmbd_smb_request()` (`protocol/common/smb_common.c:204–209`) checks
`conn->compress_algorithm == SMB3_COMPRESS_NONE` and rejects compressed requests if
compression was not negotiated. This prevents a pre-negotiation compression attack
(sending a compressed packet before any negotiate to bypass message validation). PASS.

### 5. Compression of Encrypted Sessions

`smb2_compress_resp()` (`smb2_compress.c:489`) explicitly skips compression when
`work->encrypted == true`. This correctly implements the spec requirement that encrypted
messages must not also be compressed (encryption and compression are mutually exclusive
at the message level). PASS.

### 6. Algorithm Confusion via LZ4 (0x0005)

If a malicious client sends `CompressionAlgorithm = 0x0005` in a
`COMPRESSION_TRANSFORM_HEADER` without having negotiated LZ4 (which a spec-compliant
client would never do), the server will attempt LZ4 decompression. There is no check
in `smb2_decompress_req()` that the algorithm in the transform header matches the
negotiated `conn->compress_algorithm`. This means:
- A client that negotiated Pattern_V1 can send a message with
  `CompressionAlgorithm = SMB3_COMPRESS_LZ4` in the transform header.
- The server will call `LZ4_decompress_safe()` on arbitrary client-supplied data.
- This is a **security bug**: algorithm field in the PDU should be validated against
  the negotiated algorithm (MS-SMB2 §3.3.5.2.3).

---

## Pattern_V1 Details (MS-SMB2 §2.2.42.2.3)

### Specification Layout
Per MS-XCA §2.3, a Pattern_V1 compressed payload is 8 bytes:
- Byte 0: `Pattern` (the repeated byte value)
- Byte 1: `Reserved1` (must be 0)
- Bytes 2–3: `Reserved2` (must be 0)
- Bytes 4–7: `Repetitions` (little-endian uint32, count of pattern repetitions)

### Implementation (`smb2_compress.c:50–55`)
```c
struct pattern_v1_payload {
    __u8   Pattern;
    __u8   Reserved1;
    __le16 Reserved2;
    __le32 Repetitions;
} __packed;
```

This matches the spec layout exactly. The compress function stores `src_len` as the
repetition count (`smb2_compress.c:98`), and the decompress function reconstructs via
`memset(dst, payload->Pattern, original_size)` (`smb2_compress.c:130`).

**Spec usage note:** Pattern_V1 in the spec is designed as the first pass in a chained
compression sequence (e.g., Pattern_V1 followed by LZNT1 on remaining non-pattern
data). Using it standalone in a non-chained message is technically valid in structure
but limits it to the degenerate case where the entire message is a single repeated byte.
The implementation correctly handles only this degenerate case.

---

## Confirmed Bugs (P1)

### BUG-C01: Non-Spec Algorithm LZ4 (0x0005) Exposed in Negotiate
- **File:Line:** `smb2pdu.h:316`, `smb2_negotiate.c:400–405`, `smb2_compress.c:221–231`
- **Symptom:** The server negotiates and uses LZ4 compression with algorithm ID 0x0005,
  which is not defined by MS-SMB2. No Windows or Samba client will advertise 0x0005.
  The feature is unreachable by any spec-compliant peer, and if a spec-compliant client
  sends a future algorithm with ID 0x0005 (should one be assigned), the server will
  incorrectly interpret it as LZ4.
- **Spec Ref:** MS-SMB2 §2.2.3.1.3; algorithm IDs 0–4 defined, 5 unassigned.
- **Fix:** Remove LZ4 support or implement one of LZNT1/LZ77/LZ77+Huffman using the
  kernel's `lib/lz4.c` as a backend mapped to the correct algorithm ID.

### BUG-C02: Algorithm Mismatch Not Checked on Receive
- **File:Line:** `smb2_compress.c:325–326` (reads algorithm from PDU but does not
  validate against `conn->compress_algorithm`)
- **Symptom:** A client that negotiated Pattern_V1 can send a transform header with
  `CompressionAlgorithm = SMB3_COMPRESS_LZ4 (0x0005)` or any other value. The server
  will attempt decompression with whatever algorithm the PDU claims, bypassing negotiate
  agreement. This is an algorithm-confusion vulnerability.
- **Spec Ref:** MS-SMB2 §3.3.5.2.3 — server MUST use the negotiated compression
  algorithm to decompress. If the PDU specifies a different algorithm, the server
  MUST return `STATUS_BAD_COMPRESSION_BUFFER`.
- **Fix:** After extracting `algorithm` from the transform header at `smb2_compress.c:
  325`, compare it to `work->conn->compress_algorithm` and return an error if they
  differ (exception: `SMB3_COMPRESS_NONE` in the PDU of a chained message is allowed
  to indicate an uncompressed segment).

### BUG-C03: OriginalCompressedSegmentSize Not Bounded by MaxTransactSize
- **File:Line:** `smb2_compress.c:335–347`
- **Symptom:** The decompressed size cap is `min(2MB, max_write_size)` rather than the
  spec-mandated `MaxTransactSize`. For a session with large `max_write_size`, a
  compressed WRITE carrying an embedded SMB header (which uses `MaxTransactSize`, not
  `MaxWriteSize`) could decompress a larger-than-expected buffer without a spec-compliant
  check.
- **Spec Ref:** MS-SMB2 §2.2.42 — `OriginalCompressedSegmentSize` MUST NOT exceed the
  maximum message size the server negotiated.
- **Fix:** Change the cap to use `conn->vals->max_trans_size` as the primary bound,
  with `max_write_size` used only when the compressed message is known to contain
  write data.

### BUG-C04: Pattern_V1 Used in Non-Chained Mode Violates Spec Role
- **File:Line:** `smb2_compress.c:42–46`, `smb2_negotiate.c:407–415`
- **Symptom:** The implementation selects Pattern_V1 as a standalone non-chained
  compression algorithm. Per MS-SMB2 §2.2.42.2.3, Pattern_V1 is defined for use
  only within chained compression payloads, not as a standalone non-chained algorithm.
  A Windows server will refuse to negotiate Pattern_V1 as the sole non-chained algorithm.
- **Spec Ref:** MS-SMB2 §2.2.42.2.3, §2.2.3.1.3.
- **Fix:** Either implement chained compression to properly support Pattern_V1, or
  remove Pattern_V1 from the standalone non-chained negotiate list.

### BUG-R01: RDMA Transform Header (0xFB534D42) Not Implemented
- **File:Line:** No implementation anywhere in `/home/ezechiel203/ksmbd/src`.
- **Symptom:** When RDMA encryption or signing transforms are negotiated
  (`conn->rdma_transform_count > 0` with ENCRYPTION or SIGNING IDs), no actual transform
  is applied to RDMA data. Data transmitted over `smb_direct_rdma_read/write()` is
  unprotected even when the client negotiated RDMA encryption.
- **Spec Ref:** MS-SMB2 §2.2.43 — the server MUST apply RDMA transforms when negotiated.
- **Fix:** Implement the RDMA Transform Header (`ProtocolId = 0xFB534D42`) and apply
  the negotiated transform (encrypt/sign) in `smb_direct_rdma_read()`/
  `smb_direct_rdma_write()`.

### BUG-R02: ksmbd_rdma_transform_supported() Never Called
- **File:Line:** `transport_rdma.c:228–238`; no call sites in codebase.
- **Symptom:** The function exists to query whether a transform was negotiated but
  is never used. RDMA transforms are negotiated and stored in `conn->rdma_transform_ids`
  but never enforced or applied.
- **Spec Ref:** MS-SMB2 §3.3.5.2 — RDMA transforms that are negotiated MUST be applied.
- **Fix:** Call `ksmbd_rdma_transform_supported()` in the RDMA read/write paths and
  enforce the negotiated transform.

---

## Missing Features (P2)

### P2-01: Chained Compression Not Implemented
- **File:Line:** `smb2_compress.c:319–323`
- **Description:** The chained compression flag is detected and the request is rejected
  with `-EOPNOTSUPP`. No chained decompress or compress is implemented. Chained
  compression (MS-SMB2 §2.2.42.2) is required for full SMB3.1.1 compression support.
- **Impact:** Clients that only offer chained compression (e.g., Windows 11 in some
  configurations) will fail to use compression with this server.

### P2-02: LZNT1 Decompression Not Implemented
- **File:Line:** `smb2_compress.c:267–270`
- **Description:** Clients sending LZNT1-compressed WRITEs will receive `-EOPNOTSUPP`.
  LZNT1 is the original required compression algorithm in MS-SMB2.
- **Impact:** Windows clients that negotiate and use LZNT1 (the most common Windows
  choice pre-SMB3.1.1) cannot compress writes to this server.

### P2-03: LZ77 / LZ77+Huffman Decompression Not Implemented
- **File:Line:** `smb2_compress.c:267–270`
- **Description:** Same as LZNT1. Decompression returns `-EOPNOTSUPP`.
- **Impact:** SMB3.1.1 clients preferring LZ77+Huffman (the highest-compression
  option in the spec) cannot compress writes.

### P2-04: SMB2_READFLAG_READ_COMPRESSED Not Honored
- **File:Line:** `smb2_read_write.c` (no compress flag check)
- **Description:** When a client sets `SMB2_READFLAG_READ_COMPRESSED (0x00000002)` in
  an SMB2 READ request, the server SHOULD compress the response if compression is
  negotiated. This flag is defined (`smb2pdu.h:1007`) but never checked.
- **Impact:** Per-read compression hints from the client are ignored. The server
  applies its own blanket threshold logic instead.

### P2-05: READ Responses Effectively Never Compressed (iov_cnt > 2)
- **File:Line:** `smb2_compress.c:501–503`
- **Description:** `smb2_compress_resp()` returns early when `work->iov_cnt > 2`.
  SMB2 READ responses consistently use 3 iovs (RFC1002, SMB2 header, data), so
  compression is never applied to READ responses in practice despite being negotiated.
- **Impact:** Compression is effectively limited to responses that fit in 2 iovs,
  which excludes the primary use case (file data in READ responses).

### P2-06: RDMA Transform Encryption/Signing Not Applied
- **File:Line:** `transport_rdma.c` — `smb_direct_rdma_read()` and
  `smb_direct_rdma_write()` (no transform applied)
- **Description:** Even when `SMB2_RDMA_TRANSFORM_ENCRYPTION` or
  `SMB2_RDMA_TRANSFORM_SIGNING` is negotiated, RDMA operations transmit plaintext.
- **Impact:** Security regression: clients negotiating RDMA encryption believe their
  data is protected but the server transmits it in plaintext over the RDMA fabric.

---

## Partial Implementations (P3)

### P3-01: Pattern_V1 Non-Chained Standalone Mode
- Pattern_V1 is implemented as a standalone algorithm but is spec-defined for chained
  mode only. The implementation is functionally correct for the degenerate (all-same-byte)
  case but cannot be used with compliant Windows clients for this reason.
- **File:Line:** `smb2_compress.c:70–132`

### P3-02: Compression Response Path Bypasses READ Data
- The response compression in `smb2_compress_resp()` compresses only the SMB2 response
  header body, not data in extra iovs. The comment at `smb2_compress.c:496–503` documents
  this intentional limitation. A full implementation would need to collapse multi-iov
  responses into a single buffer before compressing.
- **File:Line:** `smb2_compress.c:496–503`

### P3-03: RDMA Transform Negotiation Without Application
- RDMA transform capabilities are correctly negotiated and stored in
  `conn->rdma_transform_ids` (`connection.h:126`). The negotiate context parsing
  is well-validated. Only the actual application of negotiated transforms is missing.
- **File:Line:** `smb2_negotiate.c:501–542`, `connection.h:126–127`

---

## Low Priority (P4)

### P4-01: No Compression for Small Control Messages
- The 1024-byte threshold (`smb2pdu.h:348`) skips compression for most control
  message responses. This is a reasonable performance optimization, but the threshold
  is hardcoded rather than configurable.
- **File:Line:** `smb2_compress.c:522–523`

### P4-02: Pattern_V1 O(n) Scan
- The Pattern_V1 compressor scans the entire source buffer byte-by-byte (`smb2_compress.c:
  86–89`). For large buffers that are not uniform-byte patterns, this is wasted work.
  A SIMD-accelerated scan or an early-exit heuristic would be more efficient.
- **File:Line:** `smb2_compress.c:86–89`

### P4-03: LZ4 Working Memory Allocated per Compress Call
- `smb2_compress.c:225` allocates `LZ4_MEM_COMPRESS` (approx. 8KB) working memory
  on every compress call with `kvmalloc()` and frees it immediately after. This could
  be a per-connection pre-allocated scratch buffer.
- **File:Line:** `smb2_compress.c:225–231`

### P4-04: pr_err() in Decompression Fast Path
- Decompression failures use `pr_err()` (`smb2_compress.c:190`, `197`, `343`) which
  can be exploited by a malicious client to flood kernel logs. Should use
  `pr_err_ratelimited()`.
- **File:Line:** `smb2_compress.c:190, 197, 343, 434`

---

## Compliance Estimate

| Area                                     | Compliance |
|------------------------------------------|------------|
| Transform header structure (§2.2.42)     | 85%        |
| Algorithm negotiation (§2.2.3.1.3)       | 55%        |
| NONE algorithm                           | 100%       |
| LZNT1 algorithm                          | 5% (stub)  |
| LZ77 algorithm                           | 5% (stub)  |
| LZ77+Huffman algorithm                   | 5% (stub)  |
| Pattern_V1 algorithm (standalone only)   | 60%        |
| LZ4 (non-spec 0x0005)                    | N/A        |
| Chained compression (§2.2.42.2)          | 10% (struct only) |
| READ compressed flag (§2.2.19)           | 0%         |
| WRITE decompression pipeline             | 80%        |
| Security: decompression bomb defense     | 65%        |
| Security: algorithm confusion defense    | 10%        |
| RDMA Transform Header (§2.2.43)          | 0%         |
| RDMA Transform Capabilities negotiate    | 75%        |
| RDMA Transform enforcement               | 0%         |
| **Overall Compression + RDMA**           | **~35%**   |

**Narrative:** The compression infrastructure is partially functional for the receive
(WRITE) path with Pattern_V1 and LZ4 (non-spec). The send (READ) path compression is
architecturally broken for multi-iov responses, which covers all real-world READ
responses. Algorithm negotiation advertises a non-spec algorithm (LZ4 as 0x0005) and
does not implement the three spec-mandated algorithms (LZNT1, LZ77, LZ77+Huffman)
beyond stubs. RDMA transforms are negotiated but never applied, creating a silent
security failure for clients that negotiate RDMA encryption.
