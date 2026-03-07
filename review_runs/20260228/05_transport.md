# Transport Layer Review - ksmbd

**Reviewer:** Claude Opus 4.6
**Date:** 2026-02-28
**Scope:** transport_tcp.c/h, transport_rdma.c/h, transport_quic.c/h, transport_ipc.c/h
**Branch:** phase1-security-hardening

---

## Executive Summary

The transport layer is the first line of defense in ksmbd: it receives raw bytes from untrusted network clients and passes them to the SMB protocol processing pipeline. This review examined four transport implementations (TCP, RDMA, QUIC, IPC) totaling approximately 3,700 lines of kernel-space C code.

**Overall assessment: The transport layer is reasonably well-hardened.** The TCP and IPC transports are mature and show evidence of prior security work (connection limiting, IPC message validation with overflow checks, `GENL_ADMIN_PERM` on all netlink operations). The RDMA transport has robust SMB-Direct protocol validation. The QUIC transport is newer and employs a sound proxy architecture that keeps TLS complexity in userspace.

However, several findings warrant attention:

- **1 P0 (Critical):** RDMA data_offset validation allows an out-of-bounds read on the receive buffer.
- **3 P1 (High):** QUIC proxy trust assumptions, RDMA negotiation parameter injection, and a race condition in the TCP netdev event handler.
- **5 P2 (Medium):** Integer truncation issues, missing sendfile connection-alive checks, IPC heartbeat TOCTOU, and others.
- **6 P3 (Low/Informational):** Minor style and robustness items.

---

## Critical Findings (P0)

### P0-1: RDMA `smb_direct_check_recvmsg()` Data Offset Validation is Insufficient for Memcpy Safety

**File:** `/home/ezechiel203/ksmbd/src/transport/transport_rdma.c`, lines 554-609
**Also:** `smb_direct_read()`, lines 856-857

**Description:**

In `smb_direct_check_recvmsg()` for `SMB_DIRECT_MSG_DATA_TRANSFER`, the validation checks:

```c
if (d_offset + sizeof(struct smb2_hdr) >
    sizeof(struct smb_direct_data_transfer) +
    le32_to_cpu(req->data_length)) {
```

This validation verifies that the data_offset plus an SMB2 header fits within the *logical* data transfer structure plus data_length, but it does not verify that `d_offset` falls within the *actually received* buffer (bounded by `recvmsg->sge.length` which equals `t->max_recv_size`). A malicious client can craft a packet where `data_offset` points beyond the allocated receive buffer but still passes this check if `data_length` is set to a large value.

Later, in `smb_direct_read()` at line 857:

```c
memcpy(buf + data_read, (char *)data_transfer + data_offset + offset, to_copy);
```

The `data_offset + offset` is used to index into the `recvmsg->packet` buffer. While `recv_done()` (lines 656-670) does validate that `wc->byte_len >= data_offset + data_length`, this check happens only in the CQ completion callback. The critical issue is that `smb_direct_check_recvmsg()` is called *after* `get_first_reassembly()` in `smb_direct_prepare()` and uses the packet fields which may have been validated only by the weaker check.

More importantly, in `smb_direct_check_recvmsg()` at lines 570-573, the code actually *dereferences* the data at `recvmsg->packet + d_offset` as an `smb2_hdr` for debug logging, which is an immediate out-of-bounds read if the validation is bypassed.

**Impact:** Kernel information disclosure or crash via crafted SMB-Direct packets. An attacker on the RDMA fabric can read kernel heap memory.

**Recommendation:**

Add explicit bounds checking against the actual buffer size:

```c
if (d_offset >= recvmsg->sge.length ||
    d_offset + le32_to_cpu(req->data_length) > recvmsg->sge.length) {
    pr_err("data_offset %u + data_length %u exceeds buffer %u\n",
           d_offset, le32_to_cpu(req->data_length),
           recvmsg->sge.length);
    return -EINVAL;
}
```

Move the debug logging of the SMB2 header *after* all validation is complete, and guard it behind an additional bounds check.

---

## High Findings (P1)

### P1-1: QUIC Proxy Trust Model Allows Full Connection Spoofing by Root Processes

**File:** `/home/ezechiel203/ksmbd/src/transport/transport_quic.c`, lines 78-110, 369-413

**Description:**

The QUIC transport relies on a userspace proxy connected via a unix domain socket. The kernel validates that the peer is root (uid 0) in `verify_proxy_peer()`, but the connection metadata (client IP address, TLS verification status) is entirely self-reported by the proxy via `read_conn_info()`. The `ksmbd_quic_conn_info` structure sent by the proxy includes:

- `addr_family` and `client_addr` (trusted for per-IP limiting and logging)
- `flags` including `KSMBD_QUIC_F_TLS_VERIFIED` (trusted to mean TLS was verified)

Any root-privileged process (not just the intended QUIC proxy) can connect to the abstract unix socket `@ksmbd-quic` and inject fake connections with arbitrary source IPs, bypassing per-IP connection limits and potentially impersonating clients from any IP address.

**Impact:** A compromised or malicious root process can bypass per-IP connection limits and inject SMB sessions appearing to come from arbitrary client IPs, defeating IP-based access controls and audit trails.

**Recommendation:**

1. Add a mechanism to bind the QUIC unix socket to a specific proxy PID that is registered during startup via the IPC/netlink interface.
2. Consider using SCM_CREDENTIALS with explicit PID verification rather than just UID checking.
3. Document the trust boundary clearly: the QUIC proxy must be treated as part of the TCB (Trusted Computing Base).

### P1-2: RDMA Negotiation Allows Client to Dictate Extremely Small `max_recv_size`

**File:** `/home/ezechiel203/ksmbd/src/transport/transport_rdma.c`, lines 2186-2203

**Description:**

During SMB-Direct negotiation in `smb_direct_prepare()`:

```c
st->max_recv_size = min_t(int, st->max_recv_size,
                          le32_to_cpu(req->preferred_send_size));
st->max_send_size = min_t(int, st->max_send_size,
                          le32_to_cpu(req->max_receive_size));
```

While there is a lower bound check `if (st->max_recv_size < 1024)`, the value 1024 is extremely small for SMB operations. A client can set `preferred_send_size` to exactly 1024, forcing the server to use tiny receive buffers. The `max_fragmented_send_size` can be manipulated to 131072 (the minimum enforced at line 2202), but `max_recv_size` at 1024 would mean the server allocates many small receive buffers from the mempool, each requiring an RDMA post-receive operation. This creates a pathological workload that amplifies the credit-posting overhead and degrades server performance.

Additionally, `smb_direct_check_recvmsg()` at line 598 only enforces `max_receive_size > 128`, so a client can advertise very small receive sizes that constrain the server's sending capability to tiny fragments.

**Impact:** A malicious RDMA client can force extremely small buffer sizes, causing excessive fragmentation, credit pressure, and performance degradation (denial of service at the performance level).

**Recommendation:**

Raise the minimum `max_recv_size` to at least 8192 (to accommodate a full SMB2 header plus reasonable payload). Apply the same minimum to `max_send_size` after negotiation.

### P1-3: TCP Netdev Event Handler Race Condition on Interface State

**File:** `/home/ezechiel203/ksmbd/src/transport/transport_tcp.c`, lines 777-826

**Description:**

The `ksmbd_netdev_event()` function handles NETDEV_UP and NETDEV_DOWN events. The function calls `ksmbd_find_netdev_name_iface_list()` which acquires and releases `iface_list_lock`, then proceeds to check and modify `iface->state` *without* holding the lock:

```c
iface = ksmbd_find_netdev_name_iface_list(netdev->name);
if (iface && iface->state == IFACE_STATE_DOWN) {
    /* state checked without lock, but create_socket() modifies it */
    ret = create_socket(iface);
```

Similarly for NETDEV_DOWN:
```c
iface = ksmbd_find_netdev_name_iface_list(netdev->name);
if (iface && iface->state == IFACE_STATE_CONFIGURED) {
    kernel_sock_shutdown(iface->ksmbd_socket, SHUT_RDWR);
```

If two NETDEV events arrive rapidly (e.g., an interface bouncing), the state checks and modifications race. Two concurrent NETDEV_UP events could both see `IFACE_STATE_DOWN` and attempt to create two sockets for the same interface. Two NETDEV_DOWN events could double-free the socket.

**Impact:** Possible double socket creation, double shutdown, or use-after-free of the ksmbd_socket pointer if network interfaces bounce rapidly.

**Recommendation:**

Hold `iface_list_lock` for the entire duration of the event handling, or add a per-interface lock/state machine that prevents concurrent transitions.

---

## Medium Findings (P2)

### P2-1: Integer Type Mismatch in `kvec_array_init()` (QUIC variant)

**File:** `/home/ezechiel203/ksmbd/src/transport/transport_quic.c`, line 151

**Description:**

In the QUIC transport's `kvec_array_init()`, the local variable `copy` is declared as `int`:

```c
int copy = min(bytes, iov->iov_len);
```

But `bytes` is `size_t` and `iov->iov_len` is also `size_t`. The `min()` macro in the kernel requires matching types and this generates a compiler warning with some configurations. More importantly, if `iov->iov_len` exceeds `INT_MAX` (theoretically possible though unlikely for kernel iovecs), the `int` truncation could cause incorrect behavior.

The TCP transport's version at line 177 correctly uses `size_t copy`.

**Impact:** Low practical risk due to kernel iovec sizes, but represents a type safety issue that should match the TCP transport.

**Recommendation:**

Change `int copy` to `size_t copy` to match the TCP transport implementation.

### P2-2: `ksmbd_tcp_sendfile()` Missing Connection-Alive Check in Inner Send Loop

**File:** `/home/ezechiel203/ksmbd/src/transport/transport_tcp.c`, lines 603-616

**Description:**

The outer loop of `ksmbd_tcp_sendfile()` checks `ksmbd_conn_alive()` at line 542, but the inner send loop (`while (remaining > 0)`) does not recheck connection state. If the connection dies mid-send, the inner loop will continue attempting `sock_sendmsg()` until it gets an error from the socket layer, potentially blocking the ksmbd worker thread for up to `sk_sndtimeo` (5 seconds per attempt).

Compare with `ksmbd_tcp_writev()` which checks `ksmbd_conn_alive()` in every iteration of its send loop (line 484).

**Impact:** A ksmbd worker thread may block for an extended period sending to a dead connection, reducing server throughput under connection-failure conditions.

**Recommendation:**

Add a `ksmbd_conn_alive()` check at the top of the inner `while (remaining > 0)` loop:

```c
while (remaining > 0) {
    if (!ksmbd_conn_alive(KSMBD_TRANS(tcp_t)->conn))
        /* ... handle error ... */
    ret = sock_sendmsg(sock, &msg);
```

### P2-3: IPC Heartbeat Timer TOCTOU on `server_conf.ipc_timeout`

**File:** `/home/ezechiel203/ksmbd/src/transport/transport_ipc.c`, lines 1052-1087

**Description:**

In `__ipc_heartbeat()`, `server_conf.ipc_timeout` is read via `READ_ONCE()` multiple times throughout the function. Between reads, the value could be changed by a concurrent startup event (via `ipc_server_config_on_startup()`). This TOCTOU pattern means the heartbeat logic could use different timeout values within a single heartbeat check cycle.

For example:
1. Line 1068: `delta < READ_ONCE(server_conf.ipc_timeout)` uses value X
2. Line 1070: `READ_ONCE(server_conf.ipc_timeout) - delta` uses value Y (possibly different)

If Y < delta (because timeout was decreased between reads), this could schedule a delayed work with a negative/wrapping timeout value.

**Impact:** Unlikely practical impact due to `schedule_delayed_work()` handling unsigned long correctly, but represents a logic correctness issue.

**Recommendation:**

Read `server_conf.ipc_timeout` once at the top of `__ipc_heartbeat()` into a local variable and use that throughout:

```c
unsigned long timeout = READ_ONCE(server_conf.ipc_timeout);
if (!timeout)
    return 0;
```

### P2-4: QUIC Transport Does Not Populate `inet6_addr` for IPv6 Connections

**File:** `/home/ezechiel203/ksmbd/src/transport/transport_quic.c`, lines 452-458

**Description:**

When the QUIC proxy reports an IPv6 client, the code stores only the last 4 bytes of the IPv6 address into `conn->inet_addr`:

```c
if (t->conn_info.addr_family == AF_INET6) {
    memcpy(&conn->inet_addr,
           &t->conn_info.client_addr.v6[12], 4);
}
```

This fails to populate `conn->inet6_addr`, which the TCP transport correctly fills (line 130 of transport_tcp.c). As a result:

1. Per-IP connection limiting for IPv6 QUIC clients is based only on the last 4 bytes of the address, which for IPv4-mapped IPv6 addresses gives the correct IPv4 address, but for native IPv6 clients produces collisions (many different IPv6 addresses will hash to the same bucket).
2. The kthread name uses `%pI4` format (line 525) even for IPv6 clients, printing only the truncated address.

**Impact:** IPv6 per-IP connection limits are ineffective for native IPv6 QUIC clients. Multiple distinct IPv6 clients may be incorrectly counted as the same IP.

**Recommendation:**

For IPv6 connections, populate `conn->inet6_addr` from `t->conn_info.client_addr.v6` and use `ipv6_addr_hash()` for the hash. Update the kthread name format to handle both address families.

### P2-5: RDMA `smb_direct_read()` Reassembly Queue Lock-Free List Traversal

**File:** `/home/ezechiel203/ksmbd/src/transport/transport_rdma.c`, lines 806-905

**Description:**

The `smb_direct_read()` function performs lock-free reads of the reassembly queue based on a memory barrier pattern:

```c
if (st->reassembly_data_length >= size) {
    virt_rmb();
    queue_length = st->reassembly_queue_length;
    /* ... traverse list without lock ... */
    if (queue_length) {
        list_del(&recvmsg->list);  /* no lock! */
    } else {
        spin_lock_irq(&st->reassembly_queue_lock);
        list_del(&recvmsg->list);
        spin_unlock_irq(&st->reassembly_queue_lock);
    }
```

The comment states "we are the only one reading from the front of the queue", but this relies on the invariant that only one thread calls `smb_direct_read()` for a given transport. If this invariant were ever violated (e.g., by a future refactoring or a multi-channel scenario), the lock-free list manipulation would corrupt the list.

Additionally, the `list_del()` at line 868 (without lock, when `queue_length > 0`) modifies `recvmsg->list.prev->next`, which is a field of the *previous* list entry. If the RDMA completion callback is simultaneously adding a new entry at the tail, and the list has exactly 2 entries, the lock-free deletion could race with `list_add_tail()` in `enqueue_reassembly()`.

**Impact:** Potential list corruption under specific timing conditions. While the single-reader invariant likely holds today, the code is fragile.

**Recommendation:**

Either document the single-reader invariant with a compile-time assertion or lockdep annotation, or consistently hold the reassembly_queue_lock for all list modifications including deletions. The performance cost of the spinlock in this path is negligible compared to RDMA latency.

---

## Low/Informational (P3)

### P3-1: TCP `alloc_iface()` Leaks kstrdup'd Name if kzalloc Fails When Called from Netdev Event

**File:** `/home/ezechiel203/ksmbd/src/transport/transport_tcp.c`, lines 797-798, 875-894

**Description:**

In `ksmbd_netdev_event()` for NETDEV_UP with `bind_additional_ifaces`:

```c
iface = alloc_iface(kstrdup(netdev->name, KSMBD_DEFAULT_GFP));
```

Inside `alloc_iface()`, if `kzalloc` fails:
```c
if (!iface) {
    kfree(ifname);
    return NULL;
}
```

This correctly frees the name. However, `kstrdup()` could also return NULL (allocation failure), in which case `alloc_iface(NULL)` returns NULL without any error, which is correct. This is properly handled. **No actual bug**, but the double-allocation pattern (kstrdup then kzalloc) could be simplified to a single allocation for clarity.

**Impact:** None. Informational only.

### P3-2: QUIC Listener Has Redundant Root Check

**File:** `/home/ezechiel203/ksmbd/src/transport/transport_quic.c`, lines 567-581 and line 483

**Description:**

The QUIC listener thread performs a root UID check on the accepted socket peer at lines 567-581 in `ksmbd_quic_listener_fn()`. Then, `ksmbd_quic_new_connection()` calls `verify_proxy_peer()` (line 483) which performs an equivalent but more thorough check (also verifying peer_cred existence and reading the PID).

The first check in the listener is redundant and less thorough than the second check in `verify_proxy_peer()`.

**Impact:** No security impact -- defense in depth. But the redundancy adds code complexity.

**Recommendation:**

Remove the inline check in `ksmbd_quic_listener_fn()` and rely solely on `verify_proxy_peer()` in `ksmbd_quic_new_connection()`, which is more complete.

### P3-3: IPC `handle_response()` Copies Duplicate Replies

**File:** `/home/ezechiel203/ksmbd/src/transport/transport_ipc.c`, lines 381-383

**Description:**

```c
/* Free any prior response (e.g. duplicate reply) */
kvfree(entry->response);
entry->response = NULL;

entry->response = kvzalloc(sz, KSMBD_DEFAULT_GFP);
```

If the daemon sends a duplicate reply for the same handle, the first response is freed and replaced. This is correct behavior, but the `kvfree()` followed by immediate `kvzalloc()` is wasteful if the sizes are the same. More importantly, this indicates the code handles a scenario where the daemon misbehaves (sending duplicate replies), which could be logged.

**Impact:** Informational. No security impact.

**Recommendation:**

Add a `pr_warn_ratelimited()` when a duplicate response is received, as this indicates either a daemon bug or a replay attack.

### P3-4: RDMA `smb_direct_writev()` Contains a FIXME for RFC1002 Header Skipping

**File:** `/home/ezechiel203/ksmbd/src/transport/transport_rdma.c`, line 1368

**Description:**

```c
//FIXME: skip RFC1002 header..
if (WARN_ON_ONCE(niovs <= 1 || iov[0].iov_len != 4))
    return -EINVAL;
```

This FIXME indicates an architectural shortcoming: the upper layer always prepends a 4-byte RFC1002 length header, but RDMA transport doesn't use it (SMB-Direct has its own framing). The `WARN_ON_ONCE` catches the case where the assumption is violated, but the FIXME suggests this should be properly cleaned up.

**Impact:** Informational. The WARN_ON_ONCE is appropriate defensive coding.

### P3-5: TCP Transport `ksmbd_tcp_new_connection()` Does Not Set `max_connections` Counted Flag

**File:** `/home/ezechiel203/ksmbd/src/transport/transport_tcp.c`, lines 335-338, 625-630

**Description:**

When `ksmbd_tcp_new_connection()` fails (line 335), the active connection count is decremented. But if `ksmbd_tcp_new_connection()` succeeds, the count is never decremented until `ksmbd_tcp_disconnect()` is called (line 628-629). The disconnect correctly checks `if (server_conf.max_connections)` before decrementing.

However, if `server_conf.max_connections` is changed from non-zero to zero while connections are active (e.g., during server reconfiguration), the atomic counter `active_num_conn` will grow without bound since new connections increment it but disconnections skip the decrement. This is a minor leak of the atomic counter but does not cause a functional issue since the limit check is also skipped when `max_connections == 0`.

**Impact:** Informational. The counter becomes meaningless if `max_connections` is changed at runtime, but this does not cause harm.

### P3-6: IPC Policy Uses `NLA_BINARY` Without Length Limit for Some Event Types

**File:** `/home/ezechiel203/ksmbd/src/transport/transport_ipc.c`, lines 125-128

**Description:**

```c
[KSMBD_EVENT_RPC_REQUEST]           = { .type = NLA_BINARY },
[KSMBD_EVENT_RPC_RESPONSE]          = { .type = NLA_BINARY },
[KSMBD_EVENT_SPNEGO_AUTHEN_REQUEST] = { .type = NLA_BINARY },
[KSMBD_EVENT_SPNEGO_AUTHEN_RESPONSE]= { .type = NLA_BINARY },
```

These four policy entries use `NLA_BINARY` without a `.len` maximum, meaning the netlink layer will accept attributes of any size. While the downstream handlers (`ipc_validate_msg()`, `KSMBD_IPC_MAX_PAYLOAD` checks) apply their own validation, adding a `.len = KSMBD_IPC_MAX_PAYLOAD` to the policy would provide an additional layer of defense.

Compare with `KSMBD_EVENT_WITNESS_IFACE_LIST_RESPONSE` which correctly sets `.len = KSMBD_IPC_MAX_PAYLOAD`.

**Impact:** Low. The IPC validation is already thorough, but belt-and-suspenders is appropriate for a kernel interface.

**Recommendation:**

Add `.len = KSMBD_IPC_MAX_PAYLOAD` to all `NLA_BINARY` policy entries.

---

## Positive Observations

The following aspects of the transport layer demonstrate good security practices:

1. **TCP per-IP connection limiting** (lines 267-318 of transport_tcp.c): The implementation correctly uses a hash table with a per-bucket spinlock, checks both IPv4 and IPv6 addresses, and uses rate-limited logging to prevent log flooding.

2. **IPC privilege enforcement**: All netlink operations require `GENL_ADMIN_PERM`, and individual handlers additionally call `netlink_capable(skb, CAP_NET_ADMIN)`. The `netnsok = false` setting prevents cross-namespace attacks.

3. **IPC message validation** (`ipc_validate_msg()`, lines 581-647 of transport_ipc.c): Comprehensive use of `check_add_overflow()` and `check_mul_overflow()` for all size calculations derived from userspace-supplied data. The SPNEGO response validation checks both `session_key_len` and `spnego_blob_len` for overflow.

4. **RDMA receive buffer validation** (lines 656-679 of transport_rdma.c): The `recv_done()` CQ callback validates `wc->byte_len` against `data_offset + data_length`, and checks `remaining_data_length` and `data_length` against `max_fragmented_recv_size` with proper 64-bit arithmetic to prevent integer overflow.

5. **QUIC proxy credential verification**: The `verify_proxy_peer()` function correctly acquires `sk_peer_lock` before reading peer credentials, preventing TOCTOU races on the credential check itself.

6. **TCP keepalive configuration** (lines 88-110): Configuring TCP keepalive with idle=120s, interval=30s, count=3 provides timely detection of dead connections, preventing resource exhaustion from abandoned connections.

7. **Receive timeout enforcement**: Both TCP (`KSMBD_TCP_RECV_TIMEOUT = 7*HZ`) and QUIC (`KSMBD_QUIC_RECV_TIMEOUT = 7*HZ`) set socket receive timeouts, preventing slowloris-style attacks from blocking worker threads indefinitely.

8. **RDMA credit-based flow control**: The credit system (send credits, receive credits, R/W credits) prevents unbounded resource consumption. The `wait_for_credits()` function includes a timeout (`SMB_DIRECT_NEGOTIATE_TIMEOUT * HZ = 120s`) to prevent indefinite waits.

9. **Connection handler loop PDU size validation** (in connection.c): The handler reads the 4-byte RFC1002 header first, validates `pdu_size` against both `MAX_STREAM_PROT_LEN` (16MB) and a dynamic `max_allowed_pdu_size`, and rejects oversized PDUs before allocation. This is a critical defense against memory exhaustion.

10. **IPC overflow-safe allocation** (`ipc_msg_alloc()`, line 333): Uses `check_add_overflow()` before allocating, preventing integer overflow in the size calculation.
