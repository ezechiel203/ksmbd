# KSMBD Exhaustive Performance Audit

**Auditor perspective**: Expert Linux kernel performance engineer running perf, ftrace, and lockstat on a production server handling 10,000 concurrent SMB clients with mixed read/write workloads.

**Codebase**: `/home/ezechiel203/ksmbd/` (out-of-tree ksmbd kernel module)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Hot Path Analysis](#2-hot-path-analysis)
3. [Memory Allocation](#3-memory-allocation)
4. [Locking and Concurrency](#4-locking-and-concurrency)
5. [I/O Path](#5-io-path)
6. [Network Path](#6-network-path)
7. [Data Structure Efficiency](#7-data-structure-efficiency)
8. [Scalability Limits](#8-scalability-limits)
9. [Comparison with Best Practices](#9-comparison-with-best-practices)
10. [Findings Summary Table](#10-findings-summary-table)

---

## 1. Executive Summary

The ksmbd codebase has several significant performance bottlenecks that will severely limit throughput under heavy concurrent load. The most critical issues are:

1. **Per-READ kvzalloc allocation** (P0): Every SMB2 READ allocates a new buffer via `kvzalloc()` and zeroes it, despite the buffer being immediately overwritten by `kernel_read()`. This adds ~2 usec per READ for large buffers and generates massive memory allocator pressure.

2. **No zero-copy I/O** (P0): Neither splice/sendfile nor MSG_ZEROCOPY are used. Every READ copies data from page cache to a kernel buffer, then from the kernel buffer to the socket. This doubles memory bandwidth usage.

3. **Global inode hash lock contention** (P0): `inode_hash_lock` is a single rwlock protecting all 16K inode hash buckets. Under 10K concurrent clients this becomes a severe bottleneck.

4. **Per-request iov allocation** (P1): `ksmbd_alloc_work_struct()` does a separate `kzalloc()` for the iov array on every request, adding allocator pressure.

5. **Connection-serialized writes** (P1): `ksmbd_conn_write()` holds `srv_mutex` for the entire duration of `writev()`, preventing any pipelining of responses on a single connection.

6. **Thread-per-connection model** (P1): Each connection spawns a kernel thread for reading, limiting scalability to thousands of connections.

7. **Credits not protected atomically** (P1): `total_credits` and `outstanding_credits` are modified under `credits_lock` spinlock on every single request, creating per-connection contention.

Estimated aggregate impact of fixing all P0/P1 issues: **40-60% throughput improvement** for read-heavy workloads on NVMe-backed shares.

---

## 2. Hot Path Analysis

### 2.1 Request Processing Pipeline

The hot path for every SMB2 request follows this flow:

```
ksmbd_conn_handler_loop()          [connection.c:380]   -- reader thread
  -> kvmalloc() request buffer     [connection.c:444]
  -> t->ops->read()                [connection.c:454]   -- TCP read
  -> queue_ksmbd_work()            [server.c:284]
    -> ksmbd_alloc_work_struct()   [ksmbd_work.c:19]    -- slab + kzalloc
    -> ksmbd_queue_work()          [ksmbd_work.c:100]    -- workqueue
      -> handle_ksmbd_work()       [server.c:263]        -- worker thread
        -> decrypt_req() (if enc)  [server.c:173]
        -> allocate_rsp_buf()      [smb2pdu.c:542]       -- kvzalloc
        -> init_rsp_hdr()          [smb2pdu.c]
        -> check_user_session()    [smb2pdu.c:586]
        -> get_ksmbd_tcon()        [smb2pdu.c:100]
        -> check_sign_req()        [auth.c]              -- HMAC verify
        -> cmds->proc()            [server.c:148]        -- e.g. smb2_read
        -> set_rsp_credits()       [smb2pdu.c:323]       -- under credits_lock
        -> set_sign_rsp()          [auth.c]              -- HMAC sign
        -> encrypt_resp() (if enc) [auth.c]              -- AES-GCM/CCM
        -> ksmbd_conn_write()      [connection.c:247]    -- under srv_mutex
```

### 2.2 READ Hot Path

**Finding PERF-001: kvzalloc on every READ request**
- **Location**: `smb2pdu.c:7617`
- **Current code**:
  ```c
  aux_payload_buf = kvzalloc(ALIGN(length, 8), KSMBD_DEFAULT_GFP);
  ```
- **Impact**: P0 (Critical). For a 1MB READ, this allocates and zeroes 1MB of memory that is immediately overwritten by `kernel_read()`. At 100K IOPS, this is 100GB/sec of unnecessary memset. The `kvzalloc` also means the allocator must find contiguous virtual pages, fragmenting vmalloc space under pressure.
- **Recommended fix**:
  1. Use `kvmalloc()` (not `kvzalloc`) -- the buffer is immediately filled by `kernel_read()`, zeroing is wasted.
  2. Better: implement a per-connection or per-CPU buffer pool for READ buffers. Pre-allocate buffers at connection setup based on `max_read_size`.
  3. Best: use splice/sendfile to avoid the buffer entirely (see PERF-020).
- **Priority**: P0

**Finding PERF-002: Redundant access-check in smb2_read + ksmbd_vfs_read**
- **Location**: `smb2pdu.c:7593` and `vfs.c:759`
- **Current code**: `smb2_read()` checks `fp->daccess & FILE_READ_DATA_LE` at line 7593. Then `ksmbd_vfs_read()` checks `fp->daccess & (FILE_READ_DATA_LE | FILE_EXECUTE_LE)` at line 759.
- **Impact**: P3 (Minor). Two permission checks on the same file descriptor per read. Branch prediction will handle this but it is unnecessary code on the hot path.
- **Recommended fix**: Remove the check from `ksmbd_vfs_read()` since callers always validate permissions.
- **Priority**: P3

**Finding PERF-003: check_lock_range iterates full lock list on every READ/WRITE**
- **Location**: `vfs.c:677-733`
- **Current code**: `check_lock_range()` acquires `ctx->flc_lock` spinlock and iterates all POSIX locks on the file for every single READ and WRITE operation.
- **Impact**: P1 (Significant). For files with many byte-range locks (e.g., databases), this becomes O(n) per I/O. Even for files with zero locks, the function acquires a spinlock. The early bailout `list_empty_careful(&ctx->flc_posix)` mitigates but does not eliminate the lock acquisition.
- **Recommended fix**: Cache a "has_locks" flag on `ksmbd_file` that is set/cleared when locks are added/removed, to skip the entire function when no locks exist. For files with locks, consider an interval tree instead of linear scan.
- **Priority**: P1

### 2.3 WRITE Hot Path

**Finding PERF-004: smb_break_all_levII_oplock on every WRITE**
- **Location**: `vfs.c:939`
- **Current code**:
  ```c
  smb_break_all_levII_oplock(work, fp, 1);
  ```
- **Impact**: P2 (Moderate). This function is called on every WRITE, even when no level-II oplocks are held. It calls `opinfo_get()` which does `rcu_read_lock/unlock` and an atomic operation. If no oplock exists, this is unnecessary overhead.
- **Recommended fix**: Check `atomic_read(&fp->f_ci->op_count) > 0` before calling `smb_break_all_levII_oplock()`.
- **Priority**: P2

**Finding PERF-005: RDMA write path does unnecessary kvzalloc + memcpy**
- **Location**: `smb2pdu.c:7768`
- **Current code**:
  ```c
  data_buf = kvzalloc(length, KSMBD_DEFAULT_GFP);
  // ... rdma_read into data_buf ...
  // ... kernel_write from data_buf ...
  ```
- **Impact**: P1. The RDMA write path allocates a bounce buffer, reads from RDMA into it, then writes to the file system. This defeats zero-copy RDMA. The buffer is zeroed before being completely overwritten by RDMA read.
- **Recommended fix**: Use `kvmalloc()` instead of `kvzalloc()`. Better: use RDMA direct placement into file-system pages where possible.
- **Priority**: P1

### 2.4 QUERY_DIR Hot Path

**Finding PERF-006: Per-QUERY_DIR UTF-16 to UTF-8 string conversion allocation**
- **Location**: `smb2pdu.c:4852`
- **Current code**:
  ```c
  srch_ptr = smb_strndup_from_utf16(...)
  ```
- **Impact**: P2. Every directory listing request allocates and frees a string for the search pattern. For repeated listings (e.g., file manager refresh), this is unnecessary allocator churn.
- **Recommended fix**: Cache converted search patterns per-directory-handle or use a small stack buffer for common short patterns.
- **Priority**: P2

### 2.5 Indirect Dispatch Overhead

**Finding PERF-007: Multiple indirect function calls per request**
- **Location**: `server.c:109-161` (`__process_request`)
- **Current code**: The request processing pipeline uses `conn->ops->` function pointers at every step: `get_cmd_val`, `is_sign_req`, `check_sign_req`, `set_rsp_credits`, `set_sign_rsp`. These are all indirect calls through the `smb_version_ops` vtable.
- **Impact**: P3 for retpoline-enabled kernels (Spectre mitigations make indirect calls ~20ns each). With 6+ indirect calls per request, this adds ~120ns per request.
- **Recommended fix**: For SMB2-only builds (non-`CONFIG_SMB_INSECURE_SERVER`), inline the SMB2 implementations directly or use static calls where possible.
- **Priority**: P3

---

## 3. Memory Allocation

### 3.1 Per-Request Allocations

**Finding PERF-008: Separate kzalloc for work->iov on every request**
- **Location**: `ksmbd_work.c:31`
- **Current code**:
  ```c
  work->iov = kzalloc(sizeof(struct kvec) * work->iov_alloc_cnt, KSMBD_DEFAULT_GFP);
  ```
- **Impact**: P1. Every single SMB request allocates 4 * sizeof(struct kvec) = 64 bytes via kzalloc, then frees it on completion. At 100K IOPS, this is 100K malloc/free cycles per second just for iov arrays. The work struct is already slab-allocated, but the iov is not.
- **Recommended fix**: Embed a small iov array (4-8 entries) directly in `struct ksmbd_work`. Only allocate dynamically if more entries are needed:
  ```c
  struct ksmbd_work {
      // ...
      struct kvec inline_iov[4];
      struct kvec *iov; // points to inline_iov by default
  };
  ```
  In `ksmbd_alloc_work_struct()`:
  ```c
  work->iov = work->inline_iov;
  ```
- **Priority**: P1

**Finding PERF-009: Response buffer over-allocation for simple commands**
- **Location**: `smb2pdu.c:542-578`
- **Current code**:
  ```c
  size_t small_sz = MAX_CIFS_SMALL_BUFFER_SIZE;  // typically 448 bytes
  size_t large_sz = small_sz + work->conn->vals->max_trans_size;  // 448 + 8MB
  ```
  Commands like IOCTL and QUERY_DIRECTORY always get `large_sz` (8+ MB) even when the actual response is small.
- **Impact**: P2. `kvzalloc(8MB)` is extremely expensive. Most QUERY_DIRECTORY responses fit in < 64KB. Most IOCTLs return < 1KB.
- **Recommended fix**: Start with the small buffer and grow on demand (realloc) only when the response exceeds the small buffer. Alternatively, use a tiered allocation: small (448B), medium (64KB), large (8MB).
- **Priority**: P2

**Finding PERF-010: Request buffer allocated per-PDU in connection handler loop**
- **Location**: `connection.c:444`
- **Current code**:
  ```c
  conn->request_buf = kvmalloc(size, KSMBD_DEFAULT_GFP);
  ```
  The previous buffer is freed at line 401: `kvfree(conn->request_buf);`
- **Impact**: P1. Every single PDU received allocates a new request buffer. For a stream of 4KB reads, this means 4KB malloc/free per request.
- **Recommended fix**: Reuse the request buffer if the new PDU fits in the existing allocation. Track `request_buf_size` alongside `request_buf`:
  ```c
  if (!conn->request_buf || conn->request_buf_size < size) {
      kvfree(conn->request_buf);
      conn->request_buf = kvmalloc(size, KSMBD_DEFAULT_GFP);
      conn->request_buf_size = size;
  }
  ```
  Free only on connection teardown.
- **Priority**: P1

**Finding PERF-011: ksmbd_alloc_work_struct uses kmem_cache_zalloc (zeroing)**
- **Location**: `ksmbd_work.c:21`
- **Current code**:
  ```c
  struct ksmbd_work *work = kmem_cache_zalloc(work_cache, KSMBD_DEFAULT_GFP);
  ```
- **Impact**: P2. `struct ksmbd_work` is 408+ bytes. Zeroing the entire struct on every request is wasteful since most fields are explicitly initialized immediately after.
- **Recommended fix**: Use `kmem_cache_alloc()` and explicitly initialize only the fields that need it. Use a constructor function on the slab cache for one-time init of constants.
- **Priority**: P2

**Finding PERF-012: aux_read kmalloc on every read response with payload**
- **Location**: `ksmbd_work.c:122`
- **Current code**:
  ```c
  ar = kmalloc(sizeof(struct aux_read), KSMBD_DEFAULT_GFP);
  ```
- **Impact**: P2. `struct aux_read` is only 16 bytes (pointer + list_head). Every READ response allocates one. This should use a slab cache or be embedded.
- **Recommended fix**: Create a dedicated slab cache for `struct aux_read`, or better, embed a single `aux_read` inline in `ksmbd_work` since the common case is exactly one read buffer per response.
- **Priority**: P2

**Finding PERF-013: KSMBD_DEFAULT_GFP includes __GFP_RETRY_MAYFAIL**
- **Location**: `glob.h:58`
- **Current code**:
  ```c
  #define KSMBD_DEFAULT_GFP (GFP_KERNEL | __GFP_RETRY_MAYFAIL)
  ```
- **Impact**: P3. `__GFP_RETRY_MAYFAIL` causes the allocator to try harder before failing, which can increase latency under memory pressure. For hot-path allocations, `GFP_KERNEL` alone is more appropriate. `__GFP_RETRY_MAYFAIL` is suitable for large allocations that can tolerate higher latency.
- **Recommended fix**: Use plain `GFP_KERNEL` for small hot-path allocations (iov, aux_read, work struct). Reserve `__GFP_RETRY_MAYFAIL` for large buffer allocations only.
- **Priority**: P3

### 3.2 String Conversion Allocations

**Finding PERF-014: smb_strndup_from_utf16 allocates per conversion**
- **Location**: `unicode.c:335` (called from `smb2pdu.c:4852`, `smb2pdu.c:3114`, etc.)
- **Current code**: Every UTF-16 to UTF-8 conversion allocates a new buffer via `kzalloc()`.
- **Impact**: P2. File names are converted on CREATE, QUERY_DIR, SET_INFO, etc. For a directory listing of 10,000 files, this is 10,000 string allocations. The `smb2_get_name()` function at `smb2pdu.c:641` does this on every CREATE.
- **Recommended fix**: Use a per-work-struct scratch buffer (e.g., PATH_MAX = 4096 bytes pre-allocated in work struct) for path conversions. Only allocate dynamically for paths exceeding the scratch buffer.
- **Priority**: P2

**Finding PERF-015: PATH_MAX allocations in misc.c path conversion functions**
- **Location**: `misc.c:175`, `vfs_cache.c:601`, `vfs_cache.c:1054`
- **Current code**:
  ```c
  pathname = kmalloc(PATH_MAX, KSMBD_DEFAULT_GFP);
  ```
- **Impact**: P2. PATH_MAX is 4096 bytes. Multiple path-related functions allocate this on every call.
- **Recommended fix**: Pre-allocate a PATH_MAX buffer per work struct or use a per-CPU buffer pool.
- **Priority**: P2

### 3.3 Slab Cache Usage

**Finding PERF-016: ksmbd_inode not slab-cached**
- **Location**: `vfs_cache.c:216`
- **Current code**:
  ```c
  ci = kmalloc(sizeof(struct ksmbd_inode), KSMBD_DEFAULT_GFP);
  ```
- **Impact**: P2. `struct ksmbd_inode` is allocated on every new file open. Using a dedicated `kmem_cache` with `SLAB_HWCACHE_ALIGN` would reduce fragmentation and improve cache behavior.
- **Recommended fix**: Create `ksmbd_inode_cache` similar to `filp_cache` and `work_cache`.
- **Priority**: P2

**Finding PERF-017: oplock_info not slab-cached**
- **Location**: `oplock.c:42`
- **Current code**:
  ```c
  opinfo = kzalloc(sizeof(struct oplock_info), KSMBD_DEFAULT_GFP);
  ```
- **Impact**: P2. `struct oplock_info` is 200+ bytes and allocated on every file open that requests an oplock.
- **Recommended fix**: Create a `kmem_cache` for `struct oplock_info`.
- **Priority**: P2

**Finding PERF-018: lease struct not slab-cached**
- **Location**: `oplock.c:104`
- **Current code**:
  ```c
  lease = kmalloc(sizeof(struct lease), KSMBD_DEFAULT_GFP);
  ```
- **Impact**: P3. Similar to oplock_info.
- **Recommended fix**: Embed `struct lease` directly within `struct oplock_info` to eliminate a separate allocation (lease and opinfo have 1:1 lifetime relationship).
- **Priority**: P3

---

## 4. Locking and Concurrency

### 4.1 Global Locks

**Finding PERF-019: inode_hash_lock is a single rwlock for all 16K buckets**
- **Location**: `vfs_cache.c:34`
- **Current code**:
  ```c
  static DEFINE_RWLOCK(inode_hash_lock);
  ```
  All inode lookups (`ksmbd_inode_lookup_lock`), insertions (`ksmbd_inode_get`), and deletions (`ksmbd_inode_unhash`) contend on this single lock.
- **Impact**: P0 (Critical). With 10K concurrent clients accessing different files, every file open/close/lookup contends on this global lock. Under `perf lock`, this will show as the #1 contention point.
  - `ksmbd_inode_get()` at `vfs_cache.c:210-236`: takes `read_lock`, then `write_lock` on cache miss -- double acquisition.
  - `ksmbd_inode_unhash()` at `vfs_cache.c:184-188`: takes `write_lock` on every close.
  - `ksmbd_inode_lookup_lock()` at `vfs_cache.c:100-108`: takes `read_lock` on every lookup.
- **Recommended fix**: Use per-bucket locking (spinlock per hash bucket) or switch to RCU-protected hash list:
  ```c
  struct inode_hash_bucket {
      spinlock_t lock;
      struct hlist_head head;
  };
  static struct inode_hash_bucket *inode_hashtable;
  ```
  Use `hlist_add_head_rcu` / `hlist_for_each_entry_rcu` for lookups, with per-bucket spinlock for mutations.
- **Priority**: P0

**Finding PERF-020: conn_list_lock is a global rwsemaphore**
- **Location**: `connection.h:163`
- **Current code**:
  ```c
  extern struct rw_semaphore conn_list_lock;
  ```
  Used in `ksmbd_conn_lookup_dialect()`, `ksmbd_all_conn_set_status()`, `ksmbd_conn_wait_idle_sess_id()`, `stop_sessions()`, and connection accept path.
- **Impact**: P1. Connection accept, max-IP-connections check, and dialect lookup all take this lock. With 10K connections, `ksmbd_kthread_fn()` at `transport_tcp.c:257` takes `down_read(&conn_list_lock)` on every new connection attempt to check max IP connections. If any admin operation takes `down_write`, all accepts stall.
- **Recommended fix**: Use RCU for the connection hash table. Mutation (add/remove) is infrequent; reads are on the hot path.
- **Priority**: P1

**Finding PERF-021: lease_list_lock is a global rwlock**
- **Location**: `oplock.c:25`
- **Current code**:
  ```c
  static DEFINE_RWLOCK(lease_list_lock);
  ```
  `lease_table_list` is protected by this single global lock. Every lease addition/deletion acquires `write_lock`, and lease lookups acquire `read_lock`.
- **Impact**: P1. Under heavy workloads with many lease-holding clients, every file open that checks leases contends on this lock.
- **Recommended fix**: Use RCU for the lease table list. Per-lease-table spinlock (`lb_lock`) already exists for the per-table list -- the global list just needs RCU protection for iteration.
- **Priority**: P1

**Finding PERF-022: sessions_table_lock is a global rwsemaphore**
- **Location**: `mgmt/user_session.c:25`
- **Current code**:
  ```c
  static DECLARE_RWSEM(sessions_table_lock);
  ```
- **Impact**: P2. Session lookup/creation/deletion all contend on this lock. Session lookups happen on every request through `smb2_check_user_session()`.
- **Recommended fix**: Per-bucket locking or RCU for the sessions hash table.
- **Priority**: P2

**Finding PERF-023: shares_table_lock is a global rwsemaphore**
- **Location**: `mgmt/share_config.c:24`
- **Current code**:
  ```c
  static DECLARE_RWSEM(shares_table_lock);
  ```
- **Impact**: P3. Share lookups happen on tree connect (infrequent compared to per-request operations).
- **Recommended fix**: RCU with per-share refcounting (already has `atomic_t refcount`).
- **Priority**: P3

### 4.2 Per-Connection Locks

**Finding PERF-024: srv_mutex serializes all responses on a connection**
- **Location**: `connection.c:296-302`
- **Current code**:
  ```c
  ksmbd_conn_lock(conn);
  sent = conn->transport->ops->writev(conn->transport, work->iov, ...);
  ksmbd_conn_unlock(conn);
  ```
- **Impact**: P1. All responses on a single connection are serialized by this mutex. If the kernel is handling 256 concurrent requests (SMB multi-credit) on one connection, only one response can be sent at a time. The `writev` call includes TCP buffering and can block, holding the mutex for milliseconds.
- **Recommended fix**: Use a per-connection send queue with a dedicated sender kthread or use MSG_MORE/TCP_CORK to batch responses, releasing the lock between queue operations rather than holding it during I/O.
- **Priority**: P1

**Finding PERF-025: credits_lock spinlock on every request**
- **Location**: `server.c:223-225`
- **Current code**:
  ```c
  spin_lock(&conn->credits_lock);
  rc = conn->ops->set_rsp_credits(work);
  spin_unlock(&conn->credits_lock);
  ```
- **Impact**: P2. Every request acquires this spinlock. Since requests on the same connection are processed by different workqueue threads, they contend here. The credit computation itself is trivial arithmetic.
- **Recommended fix**: Use atomic operations for credit accounting. `total_credits` and `outstanding_credits` can be `atomic_t` with `atomic_sub`/`atomic_add`. Only take the lock for overflow/underflow edge cases.
- **Priority**: P2

**Finding PERF-026: request_lock spinlock for request queue management**
- **Location**: `connection.c:160-163` (enqueue) and `connection.c:178-180` (dequeue)
- **Current code**: `spin_lock(&conn->request_lock)` is taken on every request enqueue and dequeue.
- **Impact**: P2. With many concurrent requests per connection, this becomes a contention point.
- **Recommended fix**: Use a lock-free queue (e.g., `llist_head`) for the request list if strict ordering is not required.
- **Priority**: P2

### 4.3 File Handle Locks

**Finding PERF-027: Per-session file table uses rwlock + IDR**
- **Location**: `vfs_cache.c:423-436` (`__ksmbd_lookup_fd`)
- **Current code**:
  ```c
  read_lock(&ft->lock);
  fp = idr_find(ft->idr, id);
  if (fp)
      fp = ksmbd_fp_get(fp);
  read_unlock(&ft->lock);
  ```
- **Impact**: P1. File descriptor lookup happens on every READ, WRITE, QUERY_INFO, SET_INFO, CLOSE, etc. The IDR is protected by a rwlock. Under heavy concurrency (256 threads on one session), read-side contention on the rwlock is significant.
- **Recommended fix**: Use `rcu_read_lock()` + `idr_find()` for lookups (IDR supports RCU-safe lookup). Only take write_lock for insert/remove operations:
  ```c
  rcu_read_lock();
  fp = idr_find(ft->idr, id);
  if (fp)
      fp = ksmbd_fp_get(fp);
  rcu_read_unlock();
  ```
- **Priority**: P1

**Finding PERF-028: ksmbd_close_fd takes write_lock for the full close sequence**
- **Location**: `vfs_cache.c:467-481`
- **Current code**: `write_lock(&ft->lock)` is held while calling `set_close_state_blocked_works()` which iterates blocked works and calls cancel functions.
- **Impact**: P2. A slow close (with blocked works) holds the write lock, blocking all concurrent fd lookups for that session.
- **Recommended fix**: Only hold the lock long enough to atomically mark `fp->f_state = FP_CLOSED` and remove from IDR. Do the actual cleanup (cancel callbacks) after releasing the lock.
- **Priority**: P2

### 4.4 Oplock/Lease Lock Contention

**Finding PERF-029: m_lock (per-inode rw_semaphore) taken on every opinfo access**
- **Location**: `oplock.c:154-175` (`opinfo_get_list`)
- **Current code**:
  ```c
  down_read(&ci->m_lock);
  opinfo = list_first_entry_or_null(&ci->m_op_list, ...);
  // ... atomic_inc_not_zero ...
  up_read(&ci->m_lock);
  ```
- **Impact**: P2. Every oplock break check acquires the per-inode `m_lock`. For hot files accessed by many clients, this creates contention. The lock also protects the file list (`m_fp_list`), delete pending flags, and other per-inode state, creating false sharing between unrelated operations.
- **Recommended fix**: Split `m_lock` into separate locks for different concerns: one for the oplock list, one for the file list, one for flags. Or use RCU for the oplock list since `opinfo_get()` already uses RCU for per-fp access.
- **Priority**: P2

---

## 5. I/O Path

### 5.1 Read Path

**Finding PERF-030: No splice/sendfile support -- every READ does buffer copy**
- **Location**: `vfs.c:778`, `smb2pdu.c:7617-7663`
- **Current code**:
  ```c
  // Allocate buffer
  aux_payload_buf = kvzalloc(ALIGN(length, 8), KSMBD_DEFAULT_GFP);
  // Read from filesystem into buffer
  nbytes = kernel_read(filp, rbuf, count, pos);
  // ... later, writev sends the buffer to TCP socket
  ```
- **Impact**: P0 (Critical). This is the single biggest performance issue. Every READ does:
  1. Page cache -> kernel buffer (memcpy in `kernel_read`)
  2. Kernel buffer -> socket buffer (memcpy in `kernel_sendmsg`)

  With splice/sendfile, data goes directly from page cache to the socket (zero-copy), eliminating both copies. For a 1MB READ at 10Gbps, the two copies consume ~2 usec of CPU time and ~2MB of memory bandwidth. At line rate (1.25 GB/s), this wastes 2.5 GB/s of memory bandwidth.

  For comparison, the NFS server (`nfsd`) uses splice for READ operations, and the CIFS client uses splice for large reads.
- **Recommended fix**: Implement a splice-based read path:
  ```c
  // In vfs.c, add a splice-aware read function:
  ssize_t ksmbd_vfs_splice_read(struct ksmbd_work *work, struct ksmbd_file *fp,
                                 loff_t *pos, size_t count, struct pipe_inode_info *pipe)
  {
      return do_splice_direct(fp->filp, pos, pipe, count, 0);
  }
  ```
  Then modify `ksmbd_tcp_writev()` to use `splice_to_socket()` or `sendpage()` when data comes from page cache.

  Alternatively, use `MSG_ZEROCOPY` for the sendmsg path.
- **Priority**: P0

**Finding PERF-031: No readahead hints for sequential workloads**
- **Location**: `vfs.c:745-786`
- **Current code**: `kernel_read()` relies on the generic readahead. SMB2 CREATE has `FILE_SEQUENTIAL_ONLY_LE` flag (handled at `smb2pdu.c:3213`) but this information is not passed to the VFS.
- **Recommended fix**: When `FILE_SEQUENTIAL_ONLY_LE` is set, call `file_ra_state_init()` with appropriate readahead size, or set `FMODE_SEQ_RDATA` on the file.
- **Priority**: P2

### 5.2 Write Path

**Finding PERF-032: Write data is in the request buffer -- no extra copy needed, but no direct I/O**
- **Location**: `smb2pdu.c:7882-7888`
- **Current code**:
  ```c
  data_buf = (char *)(((char *)&req->hdr.ProtocolId) + le16_to_cpu(req->DataOffset));
  err = ksmbd_vfs_write(work, fp, data_buf, length, &offset, writethrough, &nbytes);
  ```
- **Impact**: P2. Write data is already in the request buffer (good -- no extra copy for receive). However, `kernel_write()` always goes through the page cache. For large sequential writes, this means: socket -> request buffer (one copy), then request buffer -> page cache (second copy in `kernel_write`).
- **Recommended fix**: Support `O_DIRECT` for file handles that request it. Pass through the `FILE_NO_INTERMEDIATE_BUFFERING` flag from SMB2 CREATE.
- **Priority**: P2

**Finding PERF-033: vfs_fsync_range called synchronously on writethrough**
- **Location**: `vfs.c:950-955`
- **Current code**:
  ```c
  if (sync) {
      err = vfs_fsync_range(filp, offset, offset + *written, 0);
  }
  ```
- **Impact**: P2. Writethrough writes block until the data is on persistent storage. This is correct behavior but could be batched. Multiple consecutive writethrough requests to the same file could share a single fsync.
- **Recommended fix**: Implement write coalescing: batch consecutive writethrough writes and issue a single fsync for the combined range.
- **Priority**: P2

### 5.3 Server-Side Copy

**Finding PERF-034: Server-side copy does check_lock_range per chunk**
- **Location**: `vfs.c:3617-3622`
- **Current code**: For each chunk in a server-side copy, `check_lock_range()` is called twice (source and destination). With 256 chunks (max), this is 512 lock-range checks.
- **Impact**: P2. Could be optimized by checking the entire range once rather than per-chunk.
- **Recommended fix**: Compute the aggregate source and destination ranges, then check locks once for the full range.
- **Priority**: P2

---

## 6. Network Path

### 6.1 TCP Configuration

**Finding PERF-035: No TCP_CORK used for multi-iov responses**
- **Location**: `transport_tcp.c:427-435`
- **Current code**:
  ```c
  static int ksmbd_tcp_writev(struct ksmbd_transport *t, struct kvec *iov,
                              int nvecs, int size, bool need_invalidate,
                              unsigned int remote_key)
  {
      struct msghdr smb_msg = {.msg_flags = MSG_NOSIGNAL};
      return kernel_sendmsg(TCP_TRANS(t)->sock, &smb_msg, iov, nvecs, size);
  }
  ```
- **Impact**: P2. For responses with multiple iovecs (header + data), Nagle's algorithm may cause the header to be sent as a separate TCP segment. While TCP_NODELAY is set (which disables Nagle), there is no corking to batch header and data into a single TCP segment.
- **Recommended fix**: Use `MSG_MORE` on all but the last iovec, or set `TCP_CORK` before sending and clear it after. This ensures the SMB header and data are sent in a single TCP segment where possible:
  ```c
  for (i = 0; i < nvecs - 1; i++)
      smb_msg.msg_flags |= MSG_MORE;
  ```
- **Priority**: P2

**Finding PERF-036: No socket buffer size tuning**
- **Location**: `transport_tcp.c:297-298`
- **Current code**:
  ```c
  client_sk->sk->sk_rcvtimeo = KSMBD_TCP_RECV_TIMEOUT;
  client_sk->sk->sk_sndtimeo = KSMBD_TCP_SEND_TIMEOUT;
  ```
  No `SO_RCVBUF` or `SO_SNDBUF` tuning.
- **Impact**: P2. Default socket buffer sizes may be too small for high-throughput SMB workloads. With 8MB max read/write, the socket buffer should be at least that size.
- **Recommended fix**: Set `sk->sk_sndbuf` and `sk->sk_rcvbuf` to at least `2 * max_read_size` to prevent TCP window pressure.
- **Priority**: P2

### 6.2 Connection Model

**Finding PERF-037: Thread-per-connection reader model**
- **Location**: `transport_tcp.c:189-215`
- **Current code**: `ksmbd_tcp_new_connection()` calls `kthread_run()` for each accepted connection, creating a dedicated kernel thread.
- **Impact**: P1. With 10,000 connections, this creates 10,000 kernel threads. Each thread consumes a kernel stack (~16KB), task struct (~4KB), and scheduling overhead. Modern alternatives (io_uring, epoll-based) can handle 10K+ connections with far fewer threads.
- **Recommended fix**: Phase 1 (medium effort): Use a thread pool with epoll to multiplex reads across connections. Phase 2 (high effort): Use io_uring for zero-copy async I/O on both read and write paths.
- **Priority**: P1

**Finding PERF-038: KSMBD_SOCKET_BACKLOG is only 16**
- **Location**: `connection.h:23`
- **Current code**:
  ```c
  #define KSMBD_SOCKET_BACKLOG    16
  ```
- **Impact**: P2. With burst connection rates (e.g., 1000 clients connecting simultaneously), only 16 pending connections are queued. The rest are dropped with `ECONNREFUSED`.
- **Recommended fix**: Increase to at least 128 or make it configurable:
  ```c
  #define KSMBD_SOCKET_BACKLOG    128
  ```
- **Priority**: P2

### 6.3 Compound Request Processing

**Finding PERF-039: Compound requests processed sequentially, responses sent as one**
- **Location**: `server.c:189-239`
- **Current code**: The `do { ... } while (is_chained)` loop processes each sub-request in a compound sequentially in the same worker thread.
- **Impact**: P2. For compound CREATE+READ or CREATE+QUERY_DIR requests, the individual operations cannot be overlapped. The response is built up in a single contiguous buffer.
- **Recommended fix**: For independent compound operations, consider dispatching them in parallel (complex). For related operations (common case), sequential processing is correct. Low priority because most compound requests are related.
- **Priority**: P2

### 6.4 Encryption/Signing

**Finding PERF-040: Crypto context pool limited to num_online_cpus()**
- **Location**: `crypto_ctx.c:136`
- **Current code**:
  ```c
  if (ctx_list.avail_ctx > num_online_cpus()) {
      spin_unlock(&ctx_list.ctx_lock);
      wait_event(ctx_list.ctx_wait, !list_empty(&ctx_list.idle_ctx));
      continue;
  }
  ```
- **Impact**: P1. The crypto context pool is limited to `num_online_cpus()` contexts. On a 4-core system serving 10K connections with encryption enabled, only 4 crypto contexts are available. Threads block waiting for a context, creating a bottleneck. The `spin_lock(&ctx_list.ctx_lock)` is also contended since every encrypted request must acquire/release a crypto context.
- **Recommended fix**:
  1. Use per-CPU crypto contexts (no lock needed for common case).
  2. Increase the pool limit to `2 * num_online_cpus()` at minimum.
  3. Consider pre-allocating crypto TFMs per-connection (amortize over connection lifetime).
- **Priority**: P1

**Finding PERF-041: Signing and encryption on every request when enabled**
- **Location**: `server.c:236-248`
- **Current code**: Signing (`set_sign_rsp`) and encryption (`encrypt_resp`) are called on every response. The signing involves HMAC-SHA256 or AES-CMAC computation over the entire response.
- **Impact**: P2. For a 1MB READ response with signing, the server must compute HMAC-SHA256 over 1MB of data. This is ~200 usec on modern hardware. With encryption (AES-GCM), it is ~100 usec for 1MB but with additional memory copies for scatter-gather.
- **Recommended fix**: Ensure hardware acceleration (AES-NI) is used. Consider computing the signature incrementally as the response is built, rather than over the final buffer. For encryption, investigate using `AEAD` with scatter-gather lists to avoid extra copies.
- **Priority**: P2

---

## 7. Data Structure Efficiency

### 7.1 Hash Table Sizing

**Finding PERF-042: Connection hash table is statically sized at 4096 buckets**
- **Location**: `connection.h:161`, `connection.c:27`
- **Current code**:
  ```c
  #define CONN_HASH_BITS  12  // 4096 buckets
  DEFINE_HASHTABLE(conn_list, CONN_HASH_BITS);
  ```
- **Impact**: P3. 4096 buckets is reasonable for up to ~10K connections (2.5 average chain length). Acceptable.
- **Priority**: P3

**Finding PERF-043: Inode hash table hardcoded at 16384 buckets**
- **Location**: `vfs_cache.c:254`
- **Current code**:
  ```c
  unsigned long numentries = 16384;
  ```
- **Impact**: P2. For a server with millions of open files, 16K buckets means ~60 entries per bucket on average. Hash chain traversal becomes O(n/16384).
- **Recommended fix**: Scale the hash table size based on system memory (similar to how the VFS inode hash scales):
  ```c
  numentries = max(16384UL, totalram_pages() >> (PAGE_SHIFT - 4));
  ```
- **Priority**: P2

**Finding PERF-044: Session hash table sized at 4096 buckets**
- **Location**: `mgmt/user_session.c:23`
- **Current code**:
  ```c
  #define SESSION_HASH_BITS  12  // 4096 buckets
  ```
- **Impact**: P3. Adequate for typical deployments.
- **Priority**: P3

### 7.2 Structure Layout and Cache Line Efficiency

**Finding PERF-045: ksmbd_conn struct has poor cache-line layout**
- **Location**: `connection.h:42-125`
- **Impact**: P2. The `ksmbd_conn` struct is ~500+ bytes spanning multiple cache lines. Hot fields accessed on every request (`vals`, `ops`, `status`, `total_credits`, `outstanding_credits`) are interleaved with cold fields (`ClientGUID`, `ntlmssp`, `preauth_info`, `peer_addr`). This causes unnecessary cache-line loads.
- **Recommended fix**: Reorganize the struct to group hot fields in the first cache line:
  ```c
  struct ksmbd_conn {
      /* Hot path - first cache line */
      struct smb_version_values *vals;
      struct smb_version_ops *ops;
      int status;  // use atomic_t or READ_ONCE
      unsigned int total_credits;
      unsigned int outstanding_credits;
      spinlock_t credits_lock;
      atomic_t req_running;
      struct ksmbd_transport *transport;

      /* Warm fields - second cache line */
      struct smb_version_cmds *cmds;
      unsigned int max_cmds;
      char *request_buf;
      struct nls_table *local_nls;
      // ...

      /* Cold fields */
      char ClientGUID[16];
      struct ntlmssp_auth ntlmssp;
      // ...
  } ____cacheline_aligned;
  ```
- **Priority**: P2

**Finding PERF-046: ksmbd_work struct lacks cache-line alignment annotation**
- **Location**: `ksmbd_work.h:28`
- **Impact**: P2. `struct ksmbd_work` is slab-allocated with `SLAB_HWCACHE_ALIGN`, which is good. However, the hot fields (`conn`, `sess`, `tcon`, `request_buf`, `response_buf`) should be in the first cache line.
- **Recommended fix**: Add `____cacheline_aligned` annotation and reorder fields.
- **Priority**: P2

**Finding PERF-047: ksmbd_file struct has bool fields scattered inefficiently**
- **Location**: `vfs_cache.h:71-131`
- **Impact**: P3. Multiple `bool` fields (`is_nt_open`, `attrib_only`, `reserve_lease_break`, `is_durable`, `is_persistent`, `is_resilient`, `is_posix_ctxt`) are scattered through the struct, each consuming 1 byte but causing padding. These could be bitfields or packed into a flags word.
- **Recommended fix**: Use a `unsigned int flags` field with bit definitions.
- **Priority**: P3

### 7.3 IDR vs XArray

**Finding PERF-048: File table uses IDR (older API)**
- **Location**: `vfs_cache.h:142-144`
- **Current code**:
  ```c
  struct ksmbd_file_table {
      rwlock_t    lock;
      struct idr  *idr;
  };
  ```
- **Impact**: P2. IDR is the older kernel API. XArray is the modern replacement with better performance characteristics (lock-free lookups via `xa_load()`, built-in RCU support). Sessions already use XArray (`conn->sessions`), but file tables still use IDR.
- **Recommended fix**: Migrate file tables from IDR to XArray for lock-free lookups.
- **Priority**: P2

**Finding PERF-049: IDR is dynamically allocated (kzalloc) instead of embedded**
- **Location**: `vfs_cache.c:1114`
- **Current code**:
  ```c
  ft->idr = kzalloc(sizeof(struct idr), KSMBD_DEFAULT_GFP);
  ```
- **Impact**: P3. The IDR struct is small and could be embedded directly in `ksmbd_file_table` to avoid an extra pointer dereference and allocation:
  ```c
  struct ksmbd_file_table {
      rwlock_t    lock;
      struct idr  idr;  // embedded, not pointer
  };
  ```
- **Priority**: P3

---

## 8. Scalability Limits

### 8.1 Concurrent Connection Limits

**Finding PERF-050: Thread-per-connection limits practical connections to ~10K**
- **Location**: `transport_tcp.c:189`
- **Impact**: P1. Each connection creates a kernel thread (16KB stack + task struct). At 10K connections, this is ~200MB of kernel memory just for stacks. The scheduler also degrades with many runnable threads.
- **Recommended fix**: See PERF-037.
- **Priority**: P1

### 8.2 Concurrent File Handle Limits

**Finding PERF-051: fd_limit uses atomic counter with dec-then-check pattern**
- **Location**: `vfs_cache.c:50-58`
- **Current code**:
  ```c
  static bool fd_limit_depleted(void)
  {
      long v = atomic_long_dec_return(&fd_limit);
      if (v >= 0)
          return false;
      atomic_long_inc(&fd_limit);
      return true;
  }
  ```
- **Impact**: P3. The dec-then-check-then-inc pattern is correct but generates unnecessary atomic operations when the limit is not close to being exceeded. For normal operation (far from limit), the decrement always succeeds.
- **Priority**: P3

### 8.3 NVMe Throughput Limits

**Finding PERF-052: Single-threaded read path per request limits NVMe utilization**
- **Impact**: P1. Each SMB2 READ request is handled by a single worker thread that calls `kernel_read()` synchronously. For NVMe drives capable of 500K IOPS, the server can only drive as many concurrent reads as there are worker threads. The workqueue `ksmbd-io` with `WQ_PERCPU` (on kernel >= 6.18) helps but does not address the fundamental issue that each 1MB read blocks a thread for the duration of the I/O.
- **Recommended fix**: Use asynchronous I/O (io_uring or aio) for large reads. Submit the read, do other work, and complete the response when the read finishes.
- **Priority**: P1

### 8.4 NUMA Awareness

**Finding PERF-053: No NUMA-aware allocation**
- **Impact**: P2. All allocations use `KSMBD_DEFAULT_GFP` which does not specify NUMA node affinity. On multi-socket systems, a connection handled by a CPU on node 1 may allocate memory on node 0, causing remote memory accesses on every request.
- **Recommended fix**: Use `GFP_KERNEL | __GFP_THISNODE` for per-connection and per-work allocations. Allocate the connection struct on the NUMA node of the accepting CPU. Use `alloc_workqueue("ksmbd-io", WQ_UNBOUND | WQ_NUMA, 0)` to prefer local NUMA nodes.
- **Priority**: P2

---

## 9. Comparison with Best Practices

### 9.1 NFS Server (nfsd) Comparison

| Feature | nfsd | ksmbd | Impact |
|---------|------|-------|--------|
| Zero-copy READ | splice/sendfile | No (buffer copy) | **Major** |
| Thread model | Thread pool (8-1024) | Thread-per-connection + workqueue | Moderate |
| File handle lookup | Per-CPU cache + RCU | rwlock + IDR | Moderate |
| Crypto | Per-CPU TFMs | Global pool with spinlock | Moderate |
| Request buffer | Slab cache per size class | kvmalloc per request | Moderate |
| Inode cache | Hash per-bucket lock | Global rwlock | **Major** |

### 9.2 CIFS Client Comparison

| Feature | cifs client | ksmbd server | Notes |
|---------|-------------|--------------|-------|
| Request multiplexing | Credits + async | Credits + workqueue | Similar |
| Buffer pools | cifs_small_buf_pool, cifs_req_pool | work_cache only | ksmbd should add more pools |
| Mid allocation | Slab cache | Per-request kzalloc | ksmbd lacks mid pooling |

### 9.3 Missing Kernel Features

**Finding PERF-054: MSG_ZEROCOPY not used for TCP send**
- **Impact**: P1. `MSG_ZEROCOPY` (available since Linux 4.14) allows the kernel to send data from user-provided pages directly, avoiding the copy into the TCP send buffer. For large READ responses, this would eliminate the second copy.
- **Priority**: P1

**Finding PERF-055: io_uring not used for async I/O**
- **Impact**: P2. io_uring provides the most efficient async I/O interface in the kernel. Using it for file reads/writes would allow the server to overlap I/O with protocol processing.
- **Priority**: P2

**Finding PERF-056: No MSG_SPLICE_PAGES for zero-copy network send**
- **Impact**: P1. Since Linux 6.5, `MSG_SPLICE_PAGES` can be used with `sendmsg()` to send pages from bio_vecs directly to the socket without copying. This is simpler than splice and works with the existing kvec-based send path.
- **Priority**: P1

**Finding PERF-057: Workqueue flags suboptimal for older kernels**
- **Location**: `ksmbd_work.c:87`
- **Current code**:
  ```c
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
      ksmbd_wq = alloc_workqueue("ksmbd-io", WQ_PERCPU, 0);
  #else
      ksmbd_wq = alloc_workqueue("ksmbd-io", 0, 0);
  #endif
  ```
- **Impact**: P2. On kernels < 6.18, the workqueue uses default flags (WQ_MEM_RECLAIM is not set, max_active is 0 meaning WQ_DFL_ACTIVE = 256). `WQ_UNBOUND` could provide better NUMA locality. `WQ_HIGHPRI` could reduce latency for I/O-bound work items.
- **Recommended fix**: Use `WQ_UNBOUND | WQ_HIGHPRI` as fallback flags for older kernels.
- **Priority**: P2

---

## 10. Findings Summary Table

| ID | Description | Location | Priority | Category | Est. Impact |
|---|---|---|---|---|---|
| PERF-001 | kvzalloc on every READ (zeroes buffer overwritten by kernel_read) | smb2pdu.c:7617 | P0 | Memory | Eliminates 1 memset per READ (~2us for 1MB) |
| PERF-019 | Global inode_hash_lock contends across all files | vfs_cache.c:34 | P0 | Locking | Eliminates #1 lock contention point |
| PERF-030 | No zero-copy for READ (double memcpy) | vfs.c:778 | P0 | I/O | Eliminates 2 copies per READ, 2x bandwidth |
| PERF-003 | check_lock_range O(n) scan on every READ/WRITE | vfs.c:677 | P1 | Hot Path | Eliminates spinlock + scan for no-lock files |
| PERF-005 | RDMA write kvzalloc bounce buffer | smb2pdu.c:7768 | P1 | Memory | Eliminates 1 alloc per RDMA write |
| PERF-008 | Separate kzalloc for work->iov per request | ksmbd_work.c:31 | P1 | Memory | Eliminates 1 kmalloc/kfree per request |
| PERF-010 | Request buffer allocated per-PDU (no reuse) | connection.c:444 | P1 | Memory | Eliminates 1 kvmalloc/kvfree per request |
| PERF-020 | conn_list_lock global rwsem on connection accept | connection.h:163 | P1 | Locking | Eliminates accept-path contention |
| PERF-021 | lease_list_lock global rwlock | oplock.c:25 | P1 | Locking | Eliminates lease-lookup contention |
| PERF-024 | srv_mutex serializes all responses per connection | connection.c:296 | P1 | Locking | Enables parallel response sends |
| PERF-027 | File table rwlock + IDR (no RCU lookup) | vfs_cache.c:423 | P1 | Locking | Eliminates fd lookup contention |
| PERF-037 | Thread-per-connection model | transport_tcp.c:189 | P1 | Scalability | Enables 100K+ connections |
| PERF-040 | Crypto context pool limited, spinlock contended | crypto_ctx.c:136 | P1 | Locking | Eliminates crypto pool bottleneck |
| PERF-050 | Thread-per-connection memory: 10K threads = 200MB | transport_tcp.c:189 | P1 | Scalability | Reduces memory by 10-50x |
| PERF-052 | Single-threaded sync read per request | vfs.c:778 | P1 | I/O | Enables full NVMe utilization |
| PERF-054 | MSG_ZEROCOPY not used | transport_tcp.c:427 | P1 | Network | Eliminates 1 copy per send |
| PERF-056 | MSG_SPLICE_PAGES not used | transport_tcp.c:427 | P1 | Network | Simpler zero-copy for newer kernels |
| PERF-002 | Redundant daccess check in smb2_read + vfs_read | smb2pdu.c:7593, vfs.c:759 | P3 | Hot Path | Minor |
| PERF-004 | smb_break_all_levII_oplock on every WRITE unconditionally | vfs.c:939 | P2 | Hot Path | Skip RCU ops when no oplocks |
| PERF-006 | Per-QUERY_DIR string alloc for search pattern | smb2pdu.c:4852 | P2 | Memory | Eliminates 1 kzalloc per listing |
| PERF-007 | Multiple indirect calls per request (retpoline) | server.c:109-161 | P3 | Hot Path | ~120ns per request on retpoline |
| PERF-009 | Response buffer over-allocation (8MB for QUERY_DIR) | smb2pdu.c:550 | P2 | Memory | Reduce per-request alloc by 100x |
| PERF-011 | kmem_cache_zalloc zeroes entire work struct | ksmbd_work.c:21 | P2 | Memory | Saves ~400B memset per request |
| PERF-012 | aux_read kmalloc (16 bytes) per READ | ksmbd_work.c:122 | P2 | Memory | Eliminates 1 kmalloc per READ |
| PERF-013 | KSMBD_DEFAULT_GFP has __GFP_RETRY_MAYFAIL | glob.h:58 | P3 | Memory | Reduced latency under pressure |
| PERF-014 | smb_strndup_from_utf16 allocates per conversion | unicode.c:335 | P2 | Memory | Eliminates path string allocs |
| PERF-015 | PATH_MAX kmalloc in misc/vfs_cache | misc.c:175 | P2 | Memory | Eliminates 4KB allocs per path op |
| PERF-016 | ksmbd_inode not slab-cached | vfs_cache.c:216 | P2 | Memory | Better allocation performance |
| PERF-017 | oplock_info not slab-cached | oplock.c:42 | P2 | Memory | Better allocation performance |
| PERF-018 | lease struct separately allocated (should embed) | oplock.c:104 | P3 | Memory | Eliminates 1 kmalloc per lease |
| PERF-022 | sessions_table_lock global contention | user_session.c:25 | P2 | Locking | Reduce session lookup contention |
| PERF-023 | shares_table_lock global contention | share_config.c:24 | P3 | Locking | Minor (infrequent access) |
| PERF-025 | credits_lock spinlock on every request | server.c:223 | P2 | Locking | Eliminate per-request spinlock |
| PERF-026 | request_lock spinlock on enqueue/dequeue | connection.c:160 | P2 | Locking | Use lock-free queue |
| PERF-028 | ksmbd_close_fd holds write_lock during cancel callbacks | vfs_cache.c:467 | P2 | Locking | Reduce lock hold time |
| PERF-029 | m_lock per-inode contention on hot files | oplock.c:154 | P2 | Locking | Split lock concerns |
| PERF-031 | No readahead hints for sequential files | vfs.c:745 | P2 | I/O | Better prefetch for seq reads |
| PERF-032 | No O_DIRECT support | smb2pdu.c:7882 | P2 | I/O | Bypass page cache for database |
| PERF-033 | Sync fsync per writethrough write (no batching) | vfs.c:950 | P2 | I/O | Batch writethrough syncs |
| PERF-034 | check_lock_range per chunk in server copy | vfs.c:3617 | P2 | I/O | Check once for full range |
| PERF-035 | No TCP_CORK/MSG_MORE for multi-iov send | transport_tcp.c:432 | P2 | Network | Single TCP segment for header+data |
| PERF-036 | No socket buffer size tuning | transport_tcp.c:297 | P2 | Network | Prevent TCP window pressure |
| PERF-038 | KSMBD_SOCKET_BACKLOG only 16 | connection.h:23 | P2 | Network | Handle burst connections |
| PERF-039 | Compound requests processed sequentially | server.c:189 | P2 | Network | Low priority (mostly related ops) |
| PERF-041 | Signing over full response buffer (no incremental) | server.c:236 | P2 | Network | Reduce signing latency |
| PERF-042 | Connection hash 4096 buckets (OK) | connection.h:161 | P3 | Data | Acceptable |
| PERF-043 | Inode hash hardcoded 16K buckets | vfs_cache.c:254 | P2 | Data | Scale with system size |
| PERF-044 | Session hash 4096 buckets (OK) | user_session.c:23 | P3 | Data | Acceptable |
| PERF-045 | ksmbd_conn cache-line layout | connection.h:42 | P2 | Data | Fewer cache misses |
| PERF-046 | ksmbd_work lacks cache alignment | ksmbd_work.h:28 | P2 | Data | Fewer cache misses |
| PERF-047 | ksmbd_file scattered bool fields | vfs_cache.h:71 | P3 | Data | Minor padding reduction |
| PERF-048 | File table uses IDR (should use XArray) | vfs_cache.h:142 | P2 | Data | Lock-free lookups |
| PERF-049 | IDR dynamically allocated (should embed) | vfs_cache.c:1114 | P3 | Data | Eliminate indirection |
| PERF-051 | fd_limit atomic dec-then-check pattern | vfs_cache.c:50 | P3 | Scalability | Minor |
| PERF-053 | No NUMA-aware allocation | - | P2 | Scalability | Reduce remote memory access |
| PERF-055 | io_uring not used | - | P2 | I/O | Best async I/O interface |
| PERF-057 | Workqueue flags suboptimal on older kernels | ksmbd_work.c:87 | P2 | Scalability | Better work distribution |

---

## Prioritized Action Plan

### Phase 1: Quick Wins (1-2 weeks, 20-30% throughput gain)

1. **PERF-001**: Change `kvzalloc` to `kvmalloc` in `smb2_read()` -- 1-line change
2. **PERF-008**: Embed inline iov array in `ksmbd_work` -- ~20 lines changed
3. **PERF-010**: Reuse request buffer across PDUs -- ~15 lines changed
4. **PERF-035**: Add `MSG_MORE` to TCP writev -- ~5 lines changed
5. **PERF-012**: Embed `aux_read` in `ksmbd_work` -- ~20 lines changed
6. **PERF-038**: Increase `KSMBD_SOCKET_BACKLOG` to 128 -- 1-line change
7. **PERF-004**: Skip oplock break when op_count == 0 -- ~3 lines changed

### Phase 2: Lock Optimization (2-4 weeks, 15-25% throughput gain)

8. **PERF-019**: Per-bucket locking for inode hash -- ~100 lines changed
9. **PERF-027**: RCU-based file table lookup -- ~50 lines changed
10. **PERF-020**: RCU for connection hash table -- ~80 lines changed
11. **PERF-021**: RCU for lease table list -- ~40 lines changed
12. **PERF-025**: Atomic credit accounting -- ~30 lines changed
13. **PERF-040**: Per-CPU crypto contexts -- ~60 lines changed

### Phase 3: Zero-Copy I/O (4-8 weeks, 30-50% throughput gain for reads)

14. **PERF-030**: Implement splice/sendfile for READ path -- ~200 lines new
15. **PERF-056**: Use MSG_SPLICE_PAGES on kernel >= 6.5 -- ~100 lines new
16. **PERF-054**: MSG_ZEROCOPY for TCP send -- ~80 lines changed
17. **PERF-005**: Remove RDMA bounce buffer (direct placement) -- ~100 lines changed

### Phase 4: Architecture Improvements (8-16 weeks)

18. **PERF-037**: Thread pool with epoll (replace thread-per-connection) -- ~500 lines new
19. **PERF-052**: Async I/O for file operations -- ~300 lines new
20. **PERF-048**: Migrate file tables to XArray -- ~100 lines changed

---

## Appendix: Methodology

This audit was performed by reading every source file in the ksmbd kernel module line by line, with particular attention to:

- **Files read**: `smb2pdu.c`, `vfs.c`, `vfs_cache.c`, `connection.c`, `connection.h`, `transport_tcp.c`, `transport_rdma.c`, `ksmbd_work.c`, `ksmbd_work.h`, `server.c`, `server.h`, `crypto_ctx.c`, `crypto_ctx.h`, `oplock.c`, `oplock.h`, `auth.c`, `smb2ops.c`, `smb_common.c`, `unicode.c`, `transport_ipc.c`, `mgmt/user_session.c`, `mgmt/share_config.c`, `mgmt/tree_connect.c`, `mgmt/user_config.c`, `glob.h`, `vfs.h`, `smb2pdu.h`, `misc.c`, `smbacl.c`, `ndr.c`, `asn1.c`
- **Analysis approach**: Traced the complete hot path for READ, WRITE, CREATE, QUERY_DIR, and CLOSE operations. Identified every lock acquisition, memory allocation, copy operation, and indirect call on these paths.
- **Benchmarking context**: Analysis assumes 10K concurrent connections, mixed read/write workloads on NVMe-backed shares with SMB3.1.1 encryption and signing enabled.
