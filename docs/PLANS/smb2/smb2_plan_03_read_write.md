# SMB2 Plan 03: Read / Write

**Reference:** MS-SMB2 §2.2.19–2.2.22, §3.3.5.12–3.3.5.13
**Audit date:** 2026-03-01
**Files analysed:**
- `src/protocol/smb2/smb2_read_write.c` (full)
- `src/include/protocol/smb2pdu.h` (struct defs, flag constants)
- `src/include/fs/vfs.h` / `src/include/fs/vfs_cache.h`
- `src/fs/vfs.c` (ksmbd_vfs_read, ksmbd_vfs_write, ksmbd_vfs_sendfile, ksmbd_vfs_set_fadvise)
- `src/core/smb2_compress.c` (smb2_compress_resp)

---

## Current state summary

The SMB2 READ and WRITE handlers in `smb2_read_write.c` cover the common path
well: buffered file read/write, a zero-copy sendfile fast-path, RDMA channel
support for both directions, named-pipe dispatch (async pending when no data),
write-through via `vfs_fsync_range`, append-to-EOF sentinel handling, compound
request READ/WRITE, credit accounting, and a FLUSH handler.  Global compression
infrastructure exists (`smb2_compress_resp`, `smb2_decompress_req`) and is
applied generically in `server.c` for all responses including READ.

Several spec-required behaviours are absent or partial: READ flags
(SMB2_READFLAG_READ_UNBUFFERED, SMB2_READFLAG_READ_COMPRESSED), WRITE flags
(SMB2_WRITEFLAG_WRITE_UNBUFFERED, SMB2_WRITEFLAG_REQUEST_COMPRESSED),
named-pipe DataRemaining in the response, the Padding field in the READ
response, MinimumCount short-read semantics, and pipe write flow.

Compliance is estimated at **~62 %** of the normative §3.3.5.12/13 requirements.

---

## Confirmed Bugs (P1)

### B1 — READ response DataOffset is hardcoded to 80 in all code paths

**Location:** `smb2_read_write.c:277`, `488`, `556`

`rsp->DataOffset = 80;` is a raw integer literal in three separate code paths
(pipe read, zero-copy sendfile, buffered read).  80 decimal = 0x50 is the
correct value for a normal (non-encrypted, non-compound) response because the
SMB2 header is 64 bytes and the fixed READ response header is 16 bytes (total
80), placing data at offset 80 from the start of the SMB2 message.

However, MS-SMB2 §2.2.20 specifies that `DataOffset` is measured from the
**start of the SMB2 message header** and must be consistent with the actual
layout of the returned PDU.  When the server sets `DataOffset = 80` for a
compound sub-response (the inner `smb2_read_rsp` is *not* at offset 0 of the
response buffer), the value is wrong from the client's perspective.  The
compound branch at line 562–578 avoids the scatter-gather issue by copying data
inline, but the DataOffset field still says 80 relative to the sub-response
header — which is correct for that layout.  The concern is the **lack of any
validation or dynamic calculation**: if alignment or header changes ever shift
the layout, all three sites will silently produce an incorrect offset.

More critically, the pipe-read path sets `rsp->DataOffset = 80` (line 277)
after `ksmbd_iov_pin_rsp_read` places the buffer at
`offsetof(struct smb2_read_rsp, Buffer)` = 16 bytes into the response struct.
The actual offset from the SMB2 header start is `sizeof(struct smb2_hdr) +
offsetof(struct smb2_read_rsp, Buffer)` = 64 + 16 = 80.  This is numerically
correct today but is not expressed via `offsetof`, creating a maintenance trap.

**Severity:** Correctness risk for future refactoring; currently the literal is
accurate for standard layouts.

---

### B2 — READ Offset 0xFFFFFFFFFFFFFFFF is not detected and will be silently truncated to -1

**Location:** `smb2_read_write.c:432–436`

```c
offset = le64_to_cpu(req->Offset);
if (offset < 0 || offset > MAX_LFS_FILESIZE) {
    ksmbd_debug(SMB, "invalid read offset %lld\n", offset);
    err = -EINVAL;
    goto out;
}
```

The spec (MS-SMB2 §3.3.5.12) does not define a sentinel value for READ
(unlike WRITE where 0xFFFFFFFFFFFFFFFF means append).  The check `offset < 0`
will catch the bit pattern 0xFFFFFFFFFFFFFFFF because `le64_to_cpu` returns it
as a signed `-1ll`.  The request is correctly rejected with
`STATUS_INVALID_PARAMETER`.  This is compliant behaviour.

**Correction:** Not a bug.  This item is listed here for explicitness; §3.3.5.12
does not define a special READ offset sentinel.  The validation is correct.

---

### B3 — Named pipe write: error path returns STATUS_INVALID_HANDLE for all RPC failures

**Location:** `smb2_read_write.c:656–660`

```c
if (rpc_resp->flags != KSMBD_RPC_OK) {
    rsp->hdr.Status = STATUS_INVALID_HANDLE;
    smb2_set_err_rsp(work);
    kvfree(rpc_resp);
    return ret;  /* ret is still 0 here */
}
```

`ret` is initialised to 0 and never set before this return; the function
returns 0 (success) to the caller while having written an error response.
This is a classic double-path bug: `smb2_set_err_rsp` is called, but the
return code is 0 so the caller's post-processing (e.g. compound chaining) may
treat the response as successful and attempt to build a follow-on response on
top of it.

The more appropriate status codes for pipe errors are
`STATUS_PIPE_NOT_AVAILABLE` or `STATUS_PIPE_DISCONNECTED`; `STATUS_INVALID_HANDLE`
is technically incorrect per MS-SMB2 §3.3.5.13 processing rules for named
pipes.

**File:line:** `smb2_read_write.c:657–660`

---

### B4 — WRITE RDMA path uses RemainingBytes as the I/O length, not Length

**Location:** `smb2_read_write.c:763–768`

```c
if (req->Channel == SMB2_CHANNEL_RDMA_V1 ||
    req->Channel == SMB2_CHANNEL_RDMA_V1_INVALIDATE) {
    is_rdma_channel = true;
    max_write_size = get_smbd_max_read_write_size();
    length = le32_to_cpu(req->RemainingBytes);  /* <-- uses RemainingBytes */
}
```

MS-SMB2 §2.2.21 specifies that for RDMA channels, `Length` MUST be 0 (the data
is transferred over RDMA, not inline) and `RemainingBytes` carries the total
length of the RDMA transfer.  The code deliberately uses `RemainingBytes` as
the length here, which is correct per the spec.

However, the validation at line 775 checks `req->Length != 0` correctly, but
only as part of the `is_rdma_channel` block.  If an attacker sends a crafted
RDMA request with `Length != 0` it is rejected; this part is fine.

The actual bug is that when the RDMA path calls `smb2_write_rdma_channel`, the
`length` variable was already set to `RemainingBytes`, which may be 0 if the
client sends a malformed packet.  A zero-length RDMA write is not explicitly
rejected before calling into `ksmbd_conn_rdma_read`.

**File:line:** `smb2_read_write.c:767`

---

## Missing Features (P2)

### M1 — SMB2_READFLAG_READ_UNBUFFERED: not inspected, not implemented

**Location:** `smb2_read_write.c` — no reference to `SMB2_READFLAG_READ_UNBUFFERED`
**Constant defined:** `src/include/protocol/smb2pdu.h:1006`

MS-SMB2 §3.3.5.12 step 4: if `ReadFlags` has `SMB2_READFLAG_READ_UNBUFFERED`
(0x01), the server MUST bypass its read cache and read directly from backing
store.  The Linux equivalent is re-opening the file with `O_DIRECT` or using
`kiocb` with `IOCB_DIRECT`.

`ksmbd_vfs_read` calls `kernel_read` unconditionally via the page cache
(`vfs.c:798`).  There is no code path that checks `req->Flags` for the
unbuffered bit.  The `FILE_NO_INTERMEDIATE_BUFFERING_LE` create option is
defined in `vfs.h:35` but `ksmbd_vfs_set_fadvise` (`vfs.c:2943`) does **not**
map it to `O_DIRECT`; only `FILE_WRITE_THROUGH_LE` → `O_SYNC` and read-ahead
hints are handled.

This means clients requesting unbuffered reads always get cached reads,
violating the spec.

---

### M2 — SMB2_READFLAG_READ_COMPRESSED / SMB2_WRITEFLAG_REQUEST_COMPRESSED: per-request flag ignored

**Location:** `smb2_read_write.c` — no reference to `SMB2_READFLAG_READ_COMPRESSED`
**Constants defined:** `src/include/protocol/smb2pdu.h:1007, 1012` (note: the header
uses `SMB2_READFLAG_READ_COMPRESSED` not `SMB2_READFLAG_REQUEST_COMPRESSED`)

MS-SMB2 §3.3.5.12.1 (compressed reads) and §3.3.5.13.1 (compressed writes):
when `SMB2_READFLAG_READ_COMPRESSED` is set in the READ request, the server
MUST apply compression to the response payload before sending.  Conversely,
when `SMB2_WRITEFLAG_REQUEST_COMPRESSED` is set, the client is indicating it
sent compressed write data and the server MUST decompress it.

The current implementation compresses responses generically via
`smb2_compress_resp` (called in `server.c:418`) based on whether a compression
algorithm was negotiated, but it does **not** consult the per-request
`SMB2_READFLAG_READ_COMPRESSED` bit.  Furthermore, `smb2_compress_resp` skips
multi-iov responses (`smb2_compress.c:502`), which means every normal buffered
READ with an aux-payload iov is never compressed even when the client requests
it.

For writes, `smb2_read_write.c` reads `req->Flags` only for
`SMB2_WRITEFLAG_WRITE_THROUGH` (line 883); `SMB2_WRITEFLAG_REQUEST_COMPRESSED`
is never checked.

---

### M3 — SMB2_WRITEFLAG_WRITE_UNBUFFERED: not implemented

**Location:** `smb2_read_write.c:883`

```c
if (le32_to_cpu(req->Flags) & SMB2_WRITEFLAG_WRITE_THROUGH)
    writethrough = true;
```

Only `WRITE_THROUGH` is tested.  `SMB2_WRITEFLAG_WRITE_UNBUFFERED` (0x02,
`smb2pdu.h:1012`) is never checked.  Per MS-SMB2 §3.3.5.13, when this flag is
set, the server MUST write data directly to the backing store without
intermediate buffering, equivalent to `O_DIRECT` semantics.

The flag is defined in the header but silently ignored at runtime.  A client
using `FILE_FLAG_NO_BUFFERING` on Windows will set this and expect direct I/O;
they receive buffered writes instead, which can cause data consistency issues.

---

### M4 — READ: Padding field in request never consumed

**Location:** `smb2_read_write.c:352` — `req->Padding` never read

MS-SMB2 §2.2.19 defines `Padding` (1 byte) as "the requested offset, in bytes,
from the beginning of the SMB2 header at which to place the response data."
The server is supposed to honour this to help the client align the read data
for DMA.  Although most clients send 0 or 0x50, the field is structurally
present (`smb2pdu.h:980`) and the server ignores it entirely.  The DataOffset
in the response is always fixed at 80 (lines 277/488/556), regardless of what
the client requested.

---

### M5 — MinimumCount semantics: partial implementation only

**Location:** `smb2_read_write.c:477–481`, `530–535`

```c
if ((nbytes == 0 && length != 0) || nbytes < mincount) {
    rsp->hdr.Status = STATUS_END_OF_FILE;
    ...
}
```

MS-SMB2 §3.3.5.12 states that if `MinimumCount` > 0, the server MUST NOT
return a success response with fewer bytes than `MinimumCount`; it may either
block until data is available or fail with `STATUS_END_OF_FILE`.

For regular files the current check returns `STATUS_END_OF_FILE` when
`nbytes < mincount` — this is compliant as a "fail" strategy.  However:

1. The zero-copy sendfile path (line 477) applies the check but only after
   `ksmbd_vfs_sendfile` already decided how many bytes to deliver; if
   `ksmbd_vfs_sendfile` returns a short count for a non-EOF reason (e.g., lock
   conflict returning -EAGAIN) the mincount check is skipped because the
   `nbytes < 0` branch jumps to `out`.
2. Named pipes: `smb2_read_pipe` does not propagate `mincount` to any RPC layer.
3. Blocking semantics (retry-until-mincount) are not implemented for any path.

---

### M6 — READ Channel = SMB2_CHANNEL_NONE: not validated

**Location:** `smb2_read_write.c:394–398`

The code only activates the RDMA path when `Channel` is `RDMA_V1` or
`RDMA_V1_INVALIDATE`.  MS-SMB2 §3.3.5.12 step 2 requires the server to verify
that the `Channel` field is valid and return `STATUS_INVALID_PARAMETER` for
unrecognised values.  Any Channel value other than the three defined values
(`NONE`, `RDMA_V1`, `RDMA_V1_INVALIDATE`) silently falls through to the normal
buffered read path.

---

### M7 — Named pipe write: no async support; blocking pipe writes not handled

**Location:** `smb2_read_write.c:622–681` (`smb2_write_pipe`)

The write-pipe handler is purely synchronous: it calls `ksmbd_rpc_write` and
returns.  If the RPC daemon's pipe buffer is full, the call will either block
indefinitely inside the transport layer or return an error that maps to
`STATUS_INVALID_HANDLE` (line 657).  MS-SMB2 §3.3.5.13 requires the server to
support asynchronous pipe writes when the pipe is full, sending
`STATUS_PENDING` and completing later — mirroring the async read support
added in `smb2_read_pipe_async`.  No equivalent async-write machinery exists.

---

### M8 — Write RemainingBytes field: not honoured for non-RDMA path

**Location:** `smb2_read_write.c:727–968`

For non-RDMA writes, `req->RemainingBytes` is read by the struct layout but
never used.  MS-SMB2 §2.2.21 documents `RemainingBytes` as "the number of
subsequent bytes the client intends to write."  While the spec does not require
the server to act on it (it is advisory for pipeline management), the server
MUST NOT use it as the transfer length — which is correct here — but some
implementations use it for pre-allocation or credit planning.  This is low
severity but is noted as an opportunity.

---

## Partial Implementations (P3)

### P1 — RDMA: SMB2_CHANNEL_RDMA_V1_INVALIDATE invalidation is fragile

**Location:** `smb2_read_write.c:315–319`

```c
work->need_invalidate_rkey =
    (Channel == SMB2_CHANNEL_RDMA_V1_INVALIDATE);
if (Channel == SMB2_CHANNEL_RDMA_V1_INVALIDATE)
    work->remote_key = le32_to_cpu(desc->token);
```

The `smb2_set_remote_key_for_rdma` function stores only the first descriptor's
token (`desc->token` without indexing).  For multi-descriptor RDMA buffers
(`ch_count > 1`), only the first descriptor's key is stored.  If the RDMA
transfer uses multiple Memory Region tokens, only the first is invalidated.
The per-descriptor logging loop at lines 305–311 correctly iterates all
descriptors, but the storage at line 318 accesses `desc` (pointer to first
element only).

---

### P2 — Compression of READ responses: multi-iov skip means compressed reads never work

**Location:** `src/core/smb2_compress.c:496–503`

```c
if (work->iov_cnt > 2)
    return 0;
```

Normal buffered READs set up `iov[0]` (RFC1002 + SMB2 header prefix),
`iov[1]` (READ response header), and `iov[2]` (aux payload from
`ksmbd_iov_pin_rsp_read`).  This gives `iov_cnt = 3`, which unconditionally
skips compression.  Even if a client sets `SMB2_READFLAG_READ_COMPRESSED`, the
response is never compressed.  The comment explains this as a safety measure,
but the effect is that the compression negotiated at NEGOTIATE time never
applies to read data.

---

### P3 — WRITE THROUGH: per-write fsync only; write-through open flag not applied at open time

**Location:** `vfs.c:2952–2953`

`ksmbd_vfs_set_fadvise` sets `O_SYNC` on the file if `FILE_WRITE_THROUGH_LE`
is in the `CreateOptions`.  This is correct for handles opened with
`FILE_WRITE_THROUGH`.

However, per-write `SMB2_WRITEFLAG_WRITE_THROUGH` (`smb2_read_write.c:883`)
sets `writethrough = true` and passes it to `ksmbd_vfs_write`, which calls
`vfs_fsync_range` after the write (`vfs.c:1036–1041`).  This is compliant
but is an expensive fsync per write.  More importantly, if the underlying
filesystem supports `O_SYNC` natively (e.g., ext4 with barrier), the
per-write fsync path bypasses that optimisation.

This is correct behaviour but suboptimal and could be reclassified as a
performance issue.

---

### P4 — Async READ: only named pipes go async; large file reads are synchronous

**Location:** `smb2_read_write.c:352–613`

MS-SMB2 §3.3.5.12 encourages asynchronous handling of large I/O to avoid
tying up the request processing thread.  The named-pipe path correctly uses
`setup_async_work` + `smb2_send_interim_resp` for blocking situations.
However, large file reads (`ksmbd_vfs_read` / `ksmbd_vfs_sendfile`) are fully
synchronous in the dispatch thread.  This can starve the connection's request
queue during large reads.  The spec permits (but does not mandate)
asynchronous large I/O.

---

### P5 — Compound READ+WRITE: data copy workaround may produce incorrect padding

**Location:** `smb2_read_write.c:562–578`

```c
if (work->next_smb2_rcv_hdr_off) {
    memcpy(rsp->Buffer, aux_payload_buf, nbytes);
    ksmbd_buffer_pool_put(aux_payload_buf);
    err = ksmbd_iov_pin_rsp(work, (void *)rsp,
                            offsetof(struct smb2_read_rsp, Buffer) + nbytes);
    ...
}
```

The comment explains that aux-iov layout in compound responses can cause the
8-byte inter-PDU padding to be invisible to clients.  The workaround copies
data inline.  However, MS-SMB2 §3.3.5.4 requires that each compound response
be aligned on an 8-byte boundary, and that `NextCommand` in the previous
response header points to the next 8-byte-aligned boundary.  The inline copy
places data immediately after the READ header (`Buffer[]`) with no explicit
alignment of the subsequent PDU.  Whether the outer compound builder correctly
pads after the variable-length Buffer is not verifiable from this file alone.

---

### P6 — Named pipe DataRemaining in READ response: always set to 0 for partial reads

**Location:** `smb2_read_write.c:280`

```c
rsp->DataRemaining = 0;
```

MS-SMB2 §2.2.20 specifies that `DataRemaining` in the READ response for a
named pipe indicates how many bytes remain unread in the pipe.  When the
response contains `STATUS_BUFFER_OVERFLOW` (truncated pipe data, line 245),
`DataRemaining` should indicate how much data was left in the pipe buffer that
could not fit in the response.  The current code sets `DataRemaining = 0`
even in the `STATUS_BUFFER_OVERFLOW` case, so the client cannot tell how much
more data it should attempt to read.

**File:line:** `smb2_read_write.c:280` (pipe read response) and `559` (file
read RDMA response also always sets it correctly from `remain_bytes` —
so this issue is specific to the pipe path).

---

## Low Priority (P4)

### L1 — WriteResponse DataOffset field: set to 0 (reserved) — correct but not explicit

**Location:** `smb2_read_write.c:938`

```c
rsp->DataOffset = 0;
```

MS-SMB2 §2.2.22 states `DataOffset` in the WRITE response is `Reserved` and
MUST be 0.  The code is correct.  Noted for completeness.

---

### L2 — WriteResponse DataRemaining: always 0

**Location:** `smb2_read_write.c:941`

MS-SMB2 §2.2.22: `DataRemaining` in the WRITE response is `Reserved` and
MUST be 0.  Always set to 0.  Correct.

---

### L3 — Large MTU / multi-credit: CreditCharge in request not cross-validated against Length

**Location:** `smb2_pdu_common.c:387–403`

MS-SMB2 §3.3.5.2.5 requires the server to validate that the client's
`CreditCharge` in the request header covers the actual payload size
(`CreditCharge = ceil(PayloadBytes / 65536)`).  The credit accounting in
`smb2_set_rsp_credits` (`smb2_pdu_common.c:374`) deducts `credit_charge`
(from `req_hdr->CreditCharge`) from `conn->total_credits` without checking
whether that charge is proportional to the transfer size.  A client could
charge 1 credit for a 4 MB read and the server would not notice, effectively
inflating its credit balance.

This is a flow-control/DoS hardening gap, not a correctness bug.

---

### L4 — READ request Reserved field: not validated

**Location:** `smb2_read_write.c` — `req->Reserved` never checked

MS-SMB2 §2.2.19: `Reserved` MUST be 0.  The server never validates this.  Per
spec the server MAY ignore it; this is informational.

---

### L5 — SMB2_READFLAG_REQUEST_TRANSPORT_ENCRYPTION flag: not handled

**Location:** `src/include/protocol/smb2pdu.h:1008`

`SMB2_READFLAG_REQUEST_TRANSPORT_ENCRYPTION` (0x04) is defined but never read
in `smb2_read_write.c`.  Per MS-SMB2 §2.2.19, this flag requests per-message
encryption for the response.  The encryption path is handled at the connection
level (`work->encrypted`), so per-request encryption upgrade is not possible.
Low severity; most deployments use session-level encryption.

---

### L6 — WRITE: COUNT vs DataLength — Length field validated, DataLength in response = nbytes_written

The spec differentiates the requested `Length` from bytes actually written.
The response `DataLength` is set to `nbytes` (the VFS write return value,
`smb2_read_write.c:940`).  If a partial write occurs (filesystem full mid-write)
the response correctly reports the bytes actually written.  This is compliant.

---

## Compliance estimate

| Area | Status | % |
|------|--------|---|
| READ request parsing (Length, Offset, FID, compound) | Complete | 100 |
| READ MinimumCount enforcement | Partial (fail-fast only, no blocking) | 50 |
| READ Padding honoured in response DataOffset | Missing | 0 |
| READ Flags — WRITE_THROUGH (not applicable to READ) | N/A | — |
| READ Flags — READ_UNBUFFERED | Missing | 0 |
| READ Flags — READ_COMPRESSED (per-request) | Missing | 0 |
| READ Channel NONE/RDMA_V1/RDMA_V1_INVALIDATE | Partial (no NONE validation) | 75 |
| READ RDMA channel info parsing | Present | 90 |
| READ named pipe semantics (async pending) | Present | 85 |
| READ DataRemaining for named pipes (overflow case) | Missing | 0 |
| READ response DataOffset calculation | Hardcoded literal (correct today) | 70 |
| READ large async I/O | Missing | 0 |
| WRITE request parsing (Length, Offset, Flags, FID) | Complete | 100 |
| WRITE append sentinel (0xFFFFFFFF…) | Present | 95 |
| WRITE THROUGH flag | Present (fsync per write) | 90 |
| WRITE UNBUFFERED flag | Missing | 0 |
| WRITE REQUEST_COMPRESSED flag | Missing | 0 |
| WRITE Channel RDMA | Present | 85 |
| WRITE named pipe dispatch | Present (sync only) | 60 |
| WRITE ChannelSequence validation | Present | 100 |
| WRITE Count/DataLength cross-check | Present | 95 |
| WRITE RemainingBytes (non-RDMA) | Not used (advisory) | 50 |
| Compound READ/WRITE | Partial (inline copy workaround) | 70 |
| Credit charge vs payload validation | Missing | 0 |
| SMB2 FLUSH handler | Present and complete | 95 |

**Overall READ/WRITE compliance estimate: ~62 %**

The primary compliance gaps driving the low score are the missing unbuffered
and compressed I/O paths (M1, M2, M3) which are increasingly used by modern
Windows and macOS clients, and the named-pipe DataRemaining field (P6) which
affects applications that read from DCE/RPC pipes in multiple chunks.
