# 11. Stress Tests — Server Capacity & Limits Validation

## Overview

This document defines stress tests designed to push ksmbd to its configured limits and
beyond. These tests validate that the server correctly enforces configurable limits,
degrades gracefully under load, and does not crash, leak memory, or corrupt state when
resource boundaries are hit.

**Prerequisite:** The 14 new configurable limits added in the limits audit
(KSMBD_CFG_TCP_RECV_TIMEOUT through KSMBD_CFG_SMBD_MAX_IO_SIZE) must be active
in the kernel module. Tests use both default values and custom limits set via ksmbd.conf.

### Test Infrastructure

All stress tests are **integration tests** that run against a real ksmbd server in a VM.
They use smbclient, smbclient-ng, or custom C test programs as clients.

- **VM3**: TCP transport (port 13445, SSH 13022)
- **VM4**: QUIC transport (port 14445, SSH 14022)
- **Health checks**: dmesg, slab stats, FD count, /proc/meminfo before/after each test
- **Timeout**: Per-test timeout (default 120s, configurable per category)
- **Recovery**: Module reload between categories to ensure clean state

---

## Category S01: Connection Limits

### Config Parameters Tested
- `max connections` (KSMBD_CFG_MAX_CONNECTIONS, default 1024)
- `max ip connections` (KSMBD_CFG_MAX_CONNECTIONS_PER_IP, default 64)

### Test Cases

**S01.01 — Max connections reached**
- Config: `max connections = 16`
- Open 16 SMB sessions from 16 different source ports
- Verify: All 16 succeed
- Open connection #17
- Verify: Connection #17 is rejected with appropriate error (STATUS_REQUEST_NOT_ACCEPTED or TCP RST)
- Verify: First 16 connections remain functional

**S01.02 — Max IP connections reached**
- Config: `max ip connections = 4`
- Open 4 sessions from same IP
- Verify: All 4 succeed
- Open session #5 from same IP
- Verify: Session #5 is rejected
- Verify: First 4 remain functional

**S01.03 — Connection storm (rapid connect/disconnect)**
- Config: `max connections = 256`
- Spawn 128 parallel clients, each connecting and immediately disconnecting in a loop (100 iterations)
- Verify: No ksmbd crashes (dmesg clean)
- Verify: No FD leaks (FD count returns to baseline within 10s)
- Verify: No slab leaks (slab count stable within 5%)

**S01.04 — Slowloris-style half-open connections**
- Config: `tcp recv timeout = 3`
- Open 32 TCP connections but do NOT send the SMB NEGOTIATE
- Wait 5 seconds (> tcp_recv_timeout)
- Verify: All 32 connections are cleaned up by the server
- Verify: New connections succeed after cleanup

**S01.05 — Connection limit with simultaneous I/O**
- Config: `max connections = 8`
- Open 8 connections, each performing continuous 1MB writes
- Open connection #9
- Verify: #9 rejected, #1-8 writes complete successfully

**S01.06 — Zero max connections (unlimited)**
- Config: `max connections = 0` (or absent = default 1024)
- Open 100 connections
- Verify: All succeed
- Verify: Server stable

### Expected Metrics
- Connection setup latency < 100ms under load
- No orphan connections after disconnect storm
- Memory returns to baseline within 30s of all connections closing

---

## Category S02: Session Limits

### Config Parameters Tested
- `max sessions` (KSMBD_CFG_MAX_SESSIONS, default 1024)
- `session timeout` (KSMBD_CFG_SESSION_TIMEOUT, default 10s)

### Test Cases

**S02.01 — Max sessions reached**
- Config: `max sessions = 8`
- Authenticate 8 sessions (different users or same user)
- Verify: All 8 succeed
- Attempt session #9
- Verify: Session #9 returns STATUS_REQUEST_NOT_ACCEPTED or STATUS_INSUFFICIENT_RESOURCES
- Verify: First 8 remain valid

**S02.02 — Session timeout expiration**
- Config: `session timeout = 5`
- Authenticate a session
- Do NOT send any requests for 7 seconds
- Attempt an operation on the session
- Verify: Server returns STATUS_NETWORK_SESSION_EXPIRED or similar
- Verify: New session setup succeeds after expiry

**S02.03 — Session timeout with active I/O**
- Config: `session timeout = 5`
- Authenticate a session
- Send a request every 3 seconds (within timeout)
- Verify: Session stays alive for 30+ seconds (timeout resets on activity)

**S02.04 — Mass session creation and teardown**
- Config: default (1024 max)
- Create 512 sessions, then LOGOFF all 512 in rapid succession
- Verify: No slab leaks
- Verify: Server accepts new sessions after mass teardown

**S02.05 — Session exhaust + recovery**
- Config: `max sessions = 4`
- Create 4 sessions
- LOGOFF session #2
- Create new session #5
- Verify: #5 succeeds (slot freed by logoff)
- Verify: #1, #3, #4 still valid

---

## Category S03: Credit Limits

### Config Parameters Tested
- `smb2 max credits` (KSMBD_CFG_MAX_CREDITS, default 8192)
- `max inflight requests` (KSMBD_CFG_MAX_INFLIGHT_REQ, default 8192)
- `max async credits` (KSMBD_CFG_MAX_ASYNC_CREDITS, default 512)

### Test Cases

**S03.01 — Credit exhaustion**
- Config: `smb2 max credits = 16`
- Negotiate a session with CreditRequest=1 (get 1 credit at a time)
- Send 16 requests without waiting for responses (consume all credits)
- Send request #17
- Verify: Server does not process #17 (or returns STATUS_INSUFFICIENT_CREDITS equivalent)
- Wait for responses to free credits
- Verify: New requests succeed after credits are granted back

**S03.02 — Max inflight requests**
- Config: `max inflight requests = 8`
- Send 8 requests that will block (e.g., CHANGE_NOTIFY with no changes)
- Send request #9
- Verify: #9 gets STATUS_INSUFFICIENT_RESOURCES or is queued
- Cancel one blocking request
- Verify: Queued request #9 is now processable

**S03.03 — Max async credits**
- Config: `max async credits = 4`
- Send 4 CHANGE_NOTIFY requests (async operations)
- Send CHANGE_NOTIFY #5
- Verify: #5 is rejected or queued
- Trigger a change to satisfy watch #1
- Verify: One async credit freed, new watch can be set

**S03.04 — Credit wraparound stress**
- Config: default credits
- Perform 100,000 sequential requests (reading small files)
- Verify: Credit sequence numbers wrap around correctly
- Verify: No credit counter overflow or underflow

**S03.05 — Multicredit operations**
- Config: `smb2 max credits = 64`
- Send a 4MB READ (requires multi-credit charge)
- Verify: CreditCharge is correctly calculated
- Verify: Server grants enough credits for large operations

---

## Category S04: Lock Limits

### Config Parameters Tested
- `max lock count` (KSMBD_CFG_MAX_LOCK_COUNT, default 64)

### Test Cases

**S04.01 — Max lock count per request**
- Config: `max lock count = 8`
- Send a LOCK request with 8 lock ranges
- Verify: All 8 locks granted
- Send a LOCK request with 9 lock ranges
- Verify: Returns STATUS_INVALID_PARAMETER (exceeds max_lock_count)

**S04.02 — Lock accumulation across requests**
- Config: `max lock count = 64`
- Send 64 individual LOCK requests (1 lock each) on same file
- Verify: All 64 succeed
- Send lock #65
- Verify: Behavior depends on implementation (may succeed since per-request limit, not per-file)

**S04.03 — Lock contention stress**
- Config: default
- 8 clients simultaneously locking overlapping byte ranges
- Verify: No deadlocks (all clients eventually complete)
- Verify: No lock state corruption
- Verify: Exclusive locks are mutually exclusive

**S04.04 — Lock/unlock rapid cycling**
- Config: default
- Single client: lock range, unlock, lock, unlock, ... 10,000 iterations
- Verify: No memory leaks in lock structures
- Verify: Lock state consistent at end

**S04.05 — Zero-byte lock edge case under load**
- Config: default
- 16 clients each taking zero-byte locks at offset 0
- Verify: All succeed (zero-byte locks don't conflict)
- Verify: No state corruption

**S04.06 — Lock sequence replay under contention**
- Config: default
- Client A holds lock on range [0, 1000]
- Client B sends LOCK with FAIL_IMMEDIATELY for same range (gets STATUS_LOCK_NOT_GRANTED)
- Client B retries with same LockSequence
- Verify: Replay detection returns STATUS_OK (not STATUS_LOCK_NOT_GRANTED)

---

## Category S05: File Descriptor Limits

### Config Parameters Tested
- `max open files` (KSMBD_CFG_MAX_OPEN_FILES, default 10000)

### Test Cases

**S05.01 — Max open files reached**
- Config: `max open files = 32`
- Open 32 different files (CREATE + no CLOSE)
- Verify: All 32 succeed
- Open file #33
- Verify: Returns STATUS_INSUFFICIENT_RESOURCES or STATUS_TOO_MANY_OPENED_FILES
- Close file #1
- Open file #33 again
- Verify: Succeeds (slot freed by close)

**S05.02 — Open file leak detection**
- Config: default
- Open 1000 files, close all 1000
- Verify: FD count returns to baseline
- Repeat 10 times
- Verify: No monotonic FD increase (leak detection)

**S05.03 — Durable handle exhaustion**
- Config: `max open files = 16`, durable handles enabled
- Open 16 files with durable handle request
- Disconnect client (without CLOSE)
- Reconnect and open file #17
- Verify: Behavior depends on durable handle timeout

**S05.04 — Directory enumeration with max open files**
- Config: `max open files = 8`
- Open 7 files
- Enumerate a directory with 1000 files (needs an open handle)
- Verify: Enumeration succeeds (uses 1 FD)
- Verify: 7 existing handles still valid

---

## Category S06: Buffer Size Limits

### Config Parameters Tested
- `max buffer size` (KSMBD_CFG_MAX_BUFFER_SIZE, default 65536)
- `smb2 max read` (already configurable, default 65536)
- `smb2 max write` (already configurable, default 65536)
- `smb2 max trans` (already configurable, default 65536)

### Test Cases

**S06.01 — Read at max buffer size**
- Config: `smb2 max read = 1048576` (1MB)
- Write a 4MB file
- Read with Length=1048576
- Verify: Exactly 1MB returned
- Read with Length=1048577 (1 byte over)
- Verify: Server clamps to max or returns error

**S06.02 — Write at max buffer size**
- Config: `smb2 max write = 1048576`
- Write 1048576 bytes in single request
- Verify: Write succeeds
- Write 1048577 bytes
- Verify: Server clamps or rejects

**S06.03 — Trans at max size (QUERY_INFO with large EA)**
- Config: `smb2 max trans = 65536`
- Create file with 60KB of extended attributes
- Query all EAs
- Verify: Response fits within max_trans

**S06.04 — Negotiate max sizes**
- Config: `smb2 max read = 8388608` (8MB), `smb2 max write = 8388608`, `smb2 max trans = 8388608`
- Verify: NEGOTIATE response advertises these limits
- Perform 8MB read and write operations
- Verify: Both succeed

**S06.05 — Buffer size boundary (off-by-one)**
- Config: `max buffer size = 4096`
- Send requests with payloads of exactly 4095, 4096, and 4097 bytes
- Verify: 4095 and 4096 succeed; 4097 is rejected or truncated

---

## Category S07: Timeout Limits

### Config Parameters Tested
- `tcp recv timeout` (KSMBD_CFG_TCP_RECV_TIMEOUT, default 7s)
- `tcp send timeout` (KSMBD_CFG_TCP_SEND_TIMEOUT, default 5s)
- `ipc timeout` (already configurable, default 10s)
- `deadtime` (already configurable, default 0)

### Test Cases

**S07.01 — TCP recv timeout fires**
- Config: `tcp recv timeout = 3`
- Establish SMB session
- Stop sending any data for 5 seconds
- Verify: Server closes connection (TCP RST or FIN)
- Verify: New connection succeeds

**S07.02 — TCP recv timeout does NOT fire during active I/O**
- Config: `tcp recv timeout = 3`
- Establish session
- Send requests every 2 seconds (within timeout)
- Verify: Connection stays alive for 30+ seconds

**S07.03 — Deadtime enforcement**
- Config: `deadtime = 5`
- Establish session, tree connect to share
- Do NOT access any files for 7 seconds
- Verify: Server disconnects session (deadtime expired)

**S07.04 — IPC timeout during authentication**
- Config: `ipc timeout = 2`
- Simulate slow userspace daemon (delay IPC response > 2s)
- Verify: Session setup returns STATUS_LOGON_FAILURE or similar timeout error
- Verify: Server does not hang

**S07.05 — Durable handle timeout**
- Config: `durable handle timeout = 5000` (5 seconds)
- Open file with durable handle
- Disconnect client (TCP close without LOGOFF)
- Wait 3 seconds, reconnect and reclaim handle
- Verify: Reclaim succeeds (within timeout)
- Disconnect again, wait 7 seconds
- Reconnect and try to reclaim
- Verify: Reclaim fails (handle expired)

**S07.06 — QUIC recv timeout (VM4 only)**
- Config: `quic recv timeout = 3`
- Same test as S07.01 but over QUIC transport
- Verify: QUIC connection cleaned up after timeout

---

## Category S08: Compression Stress

### Config Parameters Tested
- Compression algorithms (LZNT1, LZ77, LZ77+Huffman)
- Implicit buffer size limits

### Test Cases

**S08.01 — Compression bomb (small input, large output)**
- Config: compression enabled
- Craft a compressed payload that decompresses to 100MB from 1KB input
- Send as compressed SMB2 request
- Verify: Server rejects with STATUS_INVALID_PARAMETER or STATUS_BAD_DATA
- Verify: No OOM (check /proc/meminfo)

**S08.02 — Compression ratio limit**
- Config: compression enabled
- Send payloads with increasing compression ratios: 10:1, 100:1, 1000:1, 10000:1
- Verify: Server enforces a maximum decompressed size
- Verify: No memory exhaustion

**S08.03 — Corrupt compressed data**
- Config: compression enabled
- Send valid SMB2 transform header with corrupted compressed payload (random bytes)
- Verify: Server returns STATUS_BAD_DATA
- Verify: Connection survives (not disconnected for bad compression)

**S08.04 — All three algorithms under load**
- Config: compression enabled
- For each algorithm (LZNT1, LZ77, LZ77+Huffman):
  - Compress and send 1000 requests with random 1KB-64KB payloads
  - Verify: All decompress correctly
  - Verify: No memory leaks

**S08.05 — Compression with max buffer size**
- Config: `max buffer size = 65536`, compression enabled
- Send compressed payload that decompresses to exactly 65536 bytes
- Verify: Succeeds
- Send one that decompresses to 65537 bytes
- Verify: Fails cleanly

**S08.06 — Nested/chained compression (invalid)**
- Config: compression enabled
- Send a transform header wrapping another transform header
- Verify: Server rejects (no double decompression)

---

## Category S09: RDMA/SMBDirect Limits

### Config Parameters Tested
- `smbd max io size` (KSMBD_CFG_SMBD_MAX_IO_SIZE, default 8MB)

### Test Cases (require RDMA-capable hardware or soft-iWARP)

**S09.01 — SMBD max IO size**
- Config: `smbd max io size = 1048576` (1MB)
- Negotiate RDMA session
- Read 1MB via RDMA
- Verify: Succeeds
- Read 2MB via RDMA
- Verify: Server clamps to negotiated max or rejects

**S09.02 — RDMA connection storm**
- 16 RDMA connections simultaneously
- Each performing 64KB reads
- Verify: All complete, no RDMA resource exhaustion

**S09.03 — RDMA memory registration pressure**
- Allocate RDMA buffers until registration fails
- Verify: Server returns appropriate error (not crash)
- Free buffers and retry
- Verify: Recovery works

---

## Category S10: Compound Request Stress

### Test Cases

**S10.01 — Maximum compound chain length**
- Send compound request with 100 chained operations (CREATE+READ+CLOSE repeated)
- Verify: Server processes or rejects with appropriate limit
- Verify: No stack overflow or excessive memory use

**S10.02 — Compound with FID propagation under load**
- 8 clients simultaneously sending compound CREATE+WRITE+CLOSE
- Verify: No FID cross-contamination between compounds
- Verify: All writes land in correct files

**S10.03 — Compound with error in middle**
- Compound: CREATE(valid) + WRITE(to invalid FID) + CLOSE(compound FID)
- Verify: Error propagates correctly per MS-SMB2 3.3.5.2.7
- Verify: CLOSE uses CREATE's FID despite WRITE error

**S10.04 — Related compound across session boundary**
- Compound: SESSION_SETUP + TREE_CONNECT + CREATE
- Verify: Chaining works across session establishment

---

## Category S11: Oplock/Lease Stress

### Test Cases

**S11.01 — Mass oplock break storm**
- Client A: Open 100 files with exclusive oplocks
- Client B: Open same 100 files simultaneously
- Verify: All 100 oplock breaks sent to Client A
- Verify: All breaks acknowledged
- Verify: Client B's opens complete after break

**S11.02 — Lease break timeout**
- Client A: Open file with RWH lease
- Client B: Open same file (triggers break)
- Client A: Do NOT acknowledge break
- Wait for oplock break ack timer (default 35s)
- Verify: Server revokes lease after timeout
- Verify: Client B's open completes

**S11.03 — Lease upgrade/downgrade cycling**
- Single file, 4 clients cycling through lease states:
  R -> RH -> RWH -> R -> none
- 1000 iterations
- Verify: No lease state corruption
- Verify: No dangling lease references

---

## Category S12: Directory Enumeration Stress

### Test Cases

**S12.01 — Large directory enumeration**
- Create directory with 100,000 files
- Enumerate with QUERY_DIRECTORY (all entries)
- Verify: All 100,000 entries returned
- Verify: No duplicate entries
- Verify: Memory usage bounded

**S12.02 — Concurrent directory enumeration**
- 8 clients simultaneously enumerating same large directory (10,000 files)
- Verify: Each client gets complete, correct listing
- Verify: No interleaving between clients

**S12.03 — Directory enumeration with wildcard stress**
- Directory with 10,000 files named pattern_0001 through pattern_9999 + noise
- Enumerate with wildcard `pattern_????`
- Verify: Exactly matching files returned
- Test DOS wildcards: `<`, `>`, `"` (MS-SMB2 section 2.2.13)

**S12.04 — RESTART_SCANS stress**
- Enumerate, consume half results, then RESTART_SCANS
- Repeat 100 times
- Verify: dot/dotdot entries reset correctly each time

---

## Category S13: Authentication Stress

### Test Cases

**S13.01 — Rapid auth failure**
- Send 1000 SESSION_SETUP requests with wrong password
- Verify: All return STATUS_LOGON_FAILURE
- Verify: Server does not slow down or crash
- Verify: Valid authentication still works after failures

**S13.02 — Reauthentication under load**
- Establish session
- While I/O is active, send SESSION_SETUP to reauthenticate
- Verify: Reauthentication succeeds
- Verify: Active I/O continues with new session keys

**S13.03 — Guest fallback stress**
- Config: `map to guest = bad user`
- Send 100 SESSION_SETUP with non-existent users
- Verify: All get guest sessions
- Verify: Guest sessions can access guest-accessible shares

**S13.04 — Kerberos ticket replay**
- Send same Kerberos AP-REQ blob twice
- Verify: Second attempt is rejected (replay detection)

---

## Category S14: Notify (Change Notification) Stress

### Test Cases

**S14.01 — Max async watches**
- Config: `max async credits = 8`
- Register 8 CHANGE_NOTIFY watches on different directories
- Register watch #9
- Verify: #9 rejected (async credit exhaustion)
- Cancel watch #1
- Register watch #9 again
- Verify: Succeeds

**S14.02 — Notification flood**
- Register CHANGE_NOTIFY on directory with WATCH_TREE
- Create 10,000 files in subdirectories (triggering 10,000 notifications)
- Verify: All notifications delivered (may be coalesced)
- Verify: No notification loss
- Verify: No memory exhaustion from notification queue

**S14.03 — Watch on deleted directory**
- Register CHANGE_NOTIFY on directory
- Delete the directory from another session
- Verify: Watch is cancelled with appropriate error
- Verify: No dangling watch references

---

## Category S15: Multi-Channel / Binding Stress

### Test Cases

**S15.01 — Channel binding storm**
- Establish session on channel 1
- Bind 8 additional channels in rapid succession
- Verify: All bindings succeed
- Unbind all 8 in rapid succession
- Verify: Session remains valid on channel 1

**S15.02 — I/O across channels**
- Establish session with 4 channels
- Send READ on channel 1, WRITE on channel 2, LOCK on channel 3, QUERY on channel 4
- Verify: All operations complete correctly
- Verify: Session state consistent across channels

**S15.03 — Channel failure during I/O**
- Establish session with 2 channels
- Start large WRITE on channel 1
- Kill channel 1 mid-write
- Verify: Session survives on channel 2
- Verify: Write can be retried on channel 2

---

## Category S16: SMB1 Stress (Deprecated Protocol)

### Test Cases

**S16.01 — SMB1 max MPX**
- Config: `smb1 max mpx = 4`
- Send 4 overlapping SMB1 requests
- Verify: All 4 processed
- Send request #5 before any response
- Verify: Server queues or rejects #5

**S16.02 — SMB1 to SMB2 upgrade under load**
- Negotiate SMB1
- During active I/O, send SMB2 NEGOTIATE (dialect upgrade)
- Verify: Upgrade succeeds
- Verify: Subsequent requests use SMB2

---

## Category S17: Memory Pressure

### Test Cases

**S17.01 — Work structure exhaustion**
- Send 10,000 concurrent requests (overwhelming worker threads)
- Verify: Server queues requests, does not OOM
- Verify: All requests eventually complete or return STATUS_INSUFFICIENT_RESOURCES

**S17.02 — Large payload bombardment**
- Config: `smb2 max write = 8388608` (8MB)
- 8 clients simultaneously writing 8MB each (64MB total in-flight)
- Verify: All writes complete
- Verify: Memory returns to baseline after writes

**S17.03 — Buffer pool exhaustion**
- Allocate all buffer pool entries (rapid CREATE/QUERY cycling)
- Verify: Server falls back to kmalloc when pool exhausted
- Verify: No NULL pointer dereference

**S17.04 — Slab cache growth under sustained load**
- 1-hour sustained test: 4 clients performing continuous file operations
- Sample slab stats every 60 seconds
- Verify: Monotonic growth < 1MB/hour (no significant leaks)

---

## Category S18: Configurable Limits Boundary Tests

### Test Cases — One per new configurable parameter

**S18.01 — tcp_recv_timeout boundary (1s min, 300s max)**
- Set to 1s: Verify idle connection drops within 2s
- Set to 300s: Verify idle connection survives for 60s
- Set to 0 (absent): Verify default 7s behavior

**S18.02 — tcp_send_timeout boundary (1s min, 300s max)**
- Set to 1s: Verify slow client gets disconnected
- Set to 300s: Verify slow client survives

**S18.03 — quic_recv_timeout boundary (1s min, 300s max)**
- Same as S18.01 but over QUIC (VM4)

**S18.04 — quic_send_timeout boundary (1s min, 300s max)**
- Same as S18.02 but over QUIC (VM4)

**S18.05 — max_lock_count boundary (1 min, 1024 max)**
- Set to 1: Single lock succeeds, 2 locks in one request fails
- Set to 1024: 1024 locks in one request succeeds, 1025 fails
- Set to 0 (absent): Default 64 behavior

**S18.06 — max_buffer_size boundary (4096 min, 8388608 max)**
- Set to 4096: Verify 4KB buffer operations
- Set to 8388608: Verify 8MB buffer operations
- Verify clamping: set to 1 (below min), check gets clamped to 4096

**S18.07 — session_timeout boundary (1s min, 3600s max)**
- Set to 1s: Verify rapid session expiry
- Set to 3600s: Verify session survives 60s idle

**S18.08 — durable_handle_timeout boundary (1ms min, 600000ms max)**
- Set to 1ms: Verify immediate durable handle expiry after disconnect
- Set to 600000ms: Verify handle survives 60s after disconnect

**S18.09 — max_inflight_req boundary (1 min, 65535 max)**
- Set to 1: Verify serialized request processing
- Set to 65535: Verify no integer overflow in credit tracking

**S18.10 — max_async_credits boundary (1 min, 65535 max)**
- Set to 1: Only 1 async operation at a time
- Set to 65535: Many async operations

**S18.11 — max_open_files boundary (1 min, 65536 max)**
- Set to 1: Only 1 file open at a time
- Set to 65536: Open 1000 files

**S18.12 — max_sessions boundary (1 min, 65536 max)**
- Set to 1: Only 1 session at a time
- Set to 65536: Open 100 sessions

**S18.13 — smb1_max_mpx boundary (1 min, 50 max)**
- Set to 1: Serialized SMB1
- Set to 50: Max concurrent SMB1

**S18.14 — smbd_max_io_size boundary (512KB min, 16MB max)**
- Set to 524288: 512KB RDMA IO
- Set to 16777216: 16MB RDMA IO
- Verify clamping: set to 256KB (below min), check clamped to 512KB

---

## Implementation Priority

### Phase 1 (P0) — Must Run Before Release

| Category | Tests | Effort | Rationale |
|----------|-------|--------|-----------|
| S01 (Connection) | 6 | Medium | DoS vector |
| S02 (Session) | 5 | Medium | Auth stability |
| S04 (Lock) | 6 | Low | Known 5-bug history |
| S07 (Timeout) | 6 | Medium | New configurable params |
| S08 (Compression) | 6 | High | Security (bombs) |
| S18 (Boundaries) | 14 | Medium | New configurable params |
| **Subtotal** | **43** | | |

### Phase 2 (P1) — Should Run

| Category | Tests | Effort | Rationale |
|----------|-------|--------|-----------|
| S03 (Credit) | 5 | Medium | Flow control |
| S05 (FD) | 4 | Low | Resource management |
| S06 (Buffer) | 5 | Low | I/O correctness |
| S10 (Compound) | 4 | Medium | Known bug history |
| S11 (Oplock) | 3 | High | Concurrency |
| **Subtotal** | **21** | | |

### Phase 3 (P2) — Nice to Have

| Category | Tests | Effort | Rationale |
|----------|-------|--------|-----------|
| S09 (RDMA) | 3 | High | Hardware required |
| S12 (Directory) | 4 | Medium | Scalability |
| S13 (Auth) | 4 | Medium | Security |
| S14 (Notify) | 3 | Medium | Async correctness |
| S15 (Multichannel) | 3 | High | Complex setup |
| S16 (SMB1) | 2 | Low | Deprecated |
| S17 (Memory) | 4 | High | Long-running |
| **Subtotal** | **23** | | |

### Total: 87 stress test cases across 18 categories

---

## Test Runner Integration

Stress tests integrate with the existing ksmbd-torture framework
(see [08_KSMBD_TORTURE_DESIGN.md](08_KSMBD_TORTURE_DESIGN.md)):

```bash
# Run all stress tests
./ksmbd-torture --category stress --vm VM3

# Run specific stress category
./ksmbd-torture --category stress-connections --vm VM3

# Run with custom config
./ksmbd-torture --category stress --config stress-low-limits.conf --vm VM3

# Run boundary tests only
./ksmbd-torture --category stress-boundaries --vm VM3
```

### Custom ksmbd.conf for stress testing

```ini
[global]
    netbios name = STRESS-TEST
    server string = ksmbd stress
    workgroup = WORKGROUP

    ; Low limits for boundary testing
    max connections = 16
    max ip connections = 4
    max sessions = 8
    max open files = 32
    smb2 max credits = 16
    max inflight requests = 8
    max async credits = 4
    max lock count = 8
    tcp recv timeout = 3
    tcp send timeout = 3
    session timeout = 5
    durable handle timeout = 5000
    max buffer size = 65536
    smb1 max mpx = 4

[stress-share]
    path = /tmp/ksmbd-stress
    read only = no
    guest ok = yes
```

---

## Health Check Protocol

Before and after each stress test category:

1. **dmesg diff**: Check for kernel warnings, BUG, KASAN, UBSAN
2. **slab stats**: `/proc/slabinfo` for ksmbd-related caches
3. **FD count**: `/proc/<ksmbd-pid>/fd` count
4. **Memory**: `/proc/meminfo` (MemFree, Slab, SReclaimable)
5. **Connection count**: `/sys/kernel/debug/ksmbd/connections` (if debugfs enabled)
6. **Limits**: `/sys/kernel/debug/ksmbd/limits` (new debugfs file)

Fail the test if any of these show anomalies (leaks, warnings, crashes).
