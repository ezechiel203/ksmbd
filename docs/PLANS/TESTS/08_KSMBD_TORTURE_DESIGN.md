# ksmbd-torture: Integration Test & Benchmark Suite Design

## 1. Architecture Overview

### 1.1 Purpose

The KUnit tests in plans 01-07 exercise ksmbd internals in isolation via mocked
kernel structures. That catches logic bugs but misses an entire class of failures
that only manifest over the wire: dialect negotiation failures, credit accounting
drift, oplock break timing, compound FID propagation across commands, transport
framing errors, and resource leaks that accumulate over hundreds of operations.

**ksmbd-torture** is a grueling over-the-wire integration test and benchmark suite
that exercises the REAL ksmbd server running inside a QEMU VM. Every test sends
actual SMB packets over TCP (or QUIC), validates the server's response bytes, and
monitors the server's kernel state (dmesg, slab stats, open FDs) for side effects
that no unit test can observe.

### 1.2 Design Principles

1. **Real wire, real server.** No mocks, no stubs, no replicated logic. Every
   test talks to a live ksmbd instance over a TCP socket.
2. **Self-contained functions.** Each test is a single bash function that returns
   PASS, FAIL, or SKIP with wall-clock timing. No global state leaks between tests.
3. **Server health is a first-class signal.** After every test group, we scrape
   dmesg for BUG/WARN/OOPS/RCU stalls, check /proc/meminfo for slab growth, and
   verify the connection count returned to zero. A "silent corruption" where the
   test passes but the server is dying is treated as a FAIL.
4. **Automatic restart between heavy groups.** Oplock tests, lock stress tests,
   and reconnect storms leave residual kernel state (stale connections, cached
   share configs, leaked slabs). The runner does `ksmbdctl stop` + `rmmod ksmbd` +
   `insmod ksmbd.ko` + `ksmbdctl start` between configurable groups to guarantee
   a clean slate.
5. **Dual output.** JSON for CI pipelines (machine-parseable, exit-code-driven),
   human-readable summary with color-coded PASS/FAIL/SKIP for interactive use.
6. **Benchmark mode.** The same runner, invoked with `--benchmark`, replaces
   correctness assertions with throughput/latency measurements using fio and custom
   instrumentation.

### 1.3 Component Diagram

```
  +-------------------------------------------------------------------+
  |  Host (Arch Linux)                                                |
  |                                                                   |
  |  ksmbd-torture.sh                                                 |
  |    |                                                              |
  |    +-- lib/test_framework.sh    (register, execute, report)       |
  |    +-- lib/smb_helpers.sh       (smbclient/smbtorture wrappers)   |
  |    +-- lib/server_health.sh     (dmesg, slab, meminfo, FD count)  |
  |    +-- lib/benchmark.sh         (fio, latency, throughput)        |
  |    +-- lib/vm_control.sh        (SSH exec, module reload, start)  |
  |    +-- lib/json_output.sh       (structured JSON emitter)         |
  |    |                                                              |
  |    +-- categories/T01_negotiate.sh  ... T49_regression.sh         |
  |    +-- categories/B01_throughput.sh ... B07_compression.sh        |
  |    +-- fixtures/                     (test data files, ACLs, EAs) |
  |    +-- clients/                      (custom Python/C test tools) |
  |                                                                   |
  |  smbclient  ----+                                                 |
  |  smbtorture ----+--> TCP :13445 ---> QEMU VM3 (ksmbd)            |
  |  python3    ----+                        |                        |
  |  custom_c   ----+                        +-- SSH :13022           |
  |  fio (SMB)  ----+                        |     (health probes)    |
  |                                          |                        |
  +------------------------------------------+------------------------+
```

### 1.4 VM Topology

| VM   | SSH Port | SMB Port | Role                                |
|------|----------|----------|-------------------------------------|
| VM3  | 13022    | 13445    | Primary test target (TCP)           |
| VM4  | 14022    | 14445    | QUIC test target (when enabled)     |

The test runner defaults to VM3 but accepts `--vm VM4` (or `--vm HOST:PORT`) to
redirect all operations. QUIC tests (T33) automatically target VM4 unless
overridden.

### 1.5 Execution Flow

```
1.  Parse CLI arguments (--category, --test, --quick, --benchmark, etc.)
2.  Verify VM reachability (SSH + SMB port probe)
3.  Snapshot baseline server health (dmesg tail position, slab counts)
4.  For each selected category (in dependency order):
      a. If --restart-between: reload ksmbd module + restart daemon
      b. Create per-category temp directory on server share
      c. Execute each test function sequentially (or --parallel within category)
      d. Collect per-test result: PASS/FAIL/SKIP, wall-clock ms, stdout capture
      e. Probe server health delta (new dmesg warnings, slab growth, FD count)
      f. If crash detected: mark remaining tests CRASH, attempt server recovery
      g. Clean up per-category temp directory
5.  Aggregate results: total pass/fail/skip/crash, category summaries
6.  Emit output: JSON file + human-readable summary to stdout
7.  Exit with appropriate code (0/1/2/3)
```


## 2. Test Runner Framework

### 2.1 File Layout

```
ksmbd-torture/
  ksmbd-torture.sh                  # Main entry point (< 100 lines)
  lib/
    test_framework.sh               # Test registration, execution engine, reporting
    smb_helpers.sh                  # smbclient/smbtorture wrappers with retry
    server_health.sh                # dmesg, slab, meminfo, crash detection
    benchmark.sh                    # fio wrappers, latency/throughput calculation
    vm_control.sh                   # SSH exec, module reload, daemon restart
    json_output.sh                  # JSON array/object emitter (no jq dependency)
    assert.sh                       # Assertion helpers (assert_status, assert_file, ...)
  categories/
    T01_negotiate.sh                # One file per test category
    T02_session.sh
    ...
    T49_regression.sh
    B01_throughput.sh
    ...
    B07_compression.sh
  clients/
    raw_negotiate.py                # Raw SMB2 NEGOTIATE sender (Python, no impacket)
    credit_exhaust.py               # Credit exhaustion client
    oplock_break_timer.py           # Oplock break latency measurement
    compound_builder.py             # Arbitrary compound request builder
    quic_probe.py                   # QUIC initial handshake probe
    fid_leak.c                      # C client that opens FDs without closing
    reconnect_storm.c               # Rapid connect/disconnect stress tool
  fixtures/
    acl_templates/                  # Pre-built security descriptors
    large_file_1G.pattern           # Pattern file spec for fio verification
    ea_data/                        # Extended attribute test payloads
    smb1_dialects.bin               # Raw SMB1 negotiate payload
  results/                          # Output directory (git-ignored)
    latest.json                     # Symlink to most recent run
    YYYY-MM-DD_HHMMSS.json          # Timestamped result files
    YYYY-MM-DD_HHMMSS.log           # Full console log
```

### 2.2 Test Registration and Discovery

Each category file registers tests using a simple API:

```bash
# In categories/T01_negotiate.sh

register_test "T01.01" "negotiate_smb2_02_only" \
    --timeout 10 \
    --requires smbclient \
    --description "Negotiate with only SMB2.0.2 offered"

negotiate_smb2_02_only() {
    local share="$1"   # \\server\share
    local tmpdir="$2"  # local temp directory

    local output
    output=$(smbclient "$share" -U testuser%testpass \
        --option="client max protocol=SMB2_02" \
        --option="client min protocol=SMB2_02" \
        -c "ls" 2>&1)

    assert_status 0 $? "smbclient connection failed"
    assert_contains "$output" "blocks available" "directory listing missing"
    return 0
}
```

The framework discovers tests by sourcing all `categories/*.sh` files and
collecting functions registered via `register_test`. Registration metadata
includes:

| Field         | Purpose                                              |
|---------------|------------------------------------------------------|
| `id`          | Unique dotted identifier (T01.01, B03.07, etc.)     |
| `function`    | Bash function name to invoke                         |
| `timeout`     | Per-test timeout in seconds (default: 30)            |
| `requires`    | Tool dependencies (smbclient, smbtorture, python3)   |
| `tags`        | Freeform tags for filtering (slow, destructive, quic) |
| `description` | One-line human-readable description                  |
| `after`       | Test IDs that must run first (ordering dependency)    |

### 2.3 Test Execution Engine

```bash
# Pseudocode for the execution loop (lib/test_framework.sh)

run_category() {
    local category="$1"
    local tests=( $(get_tests_for_category "$category") )

    if [[ "$RESTART_BETWEEN" == "yes" ]]; then
        vm_reload_ksmbd
    fi

    local share="\\\\${VM_HOST}\\${SHARE_NAME}"
    local server_tmpdir
    server_tmpdir=$(vm_exec "mktemp -d /srv/smb/testshare/torture_XXXXXX")

    local pass=0 fail=0 skip=0
    for test_id in "${tests[@]}"; do
        local func timeout requires
        func=$(get_test_func "$test_id")
        timeout=$(get_test_timeout "$test_id")
        requires=$(get_test_requires "$test_id")

        # Check tool requirements
        if ! check_requirements "$requires"; then
            record_result "$test_id" "SKIP" 0 "missing: $requires"
            ((skip++))
            continue
        fi

        # Execute with timeout
        local start_ms elapsed_ms exit_code output
        start_ms=$(date +%s%3N)
        output=$(timeout "${timeout}s" bash -c "$func '$share' '$local_tmpdir'" 2>&1)
        exit_code=$?
        elapsed_ms=$(( $(date +%s%3N) - start_ms ))

        if [[ $exit_code -eq 0 ]]; then
            record_result "$test_id" "PASS" "$elapsed_ms" ""
            ((pass++))
        elif [[ $exit_code -eq 124 ]]; then
            record_result "$test_id" "FAIL" "$elapsed_ms" "TIMEOUT after ${timeout}s"
            ((fail++))
        else
            record_result "$test_id" "FAIL" "$elapsed_ms" "$output"
            ((fail++))
        fi
    done

    # Post-category health check
    local health
    health=$(check_server_health)
    if [[ "$health" != "OK" ]]; then
        record_health_event "$category" "$health"
    fi

    vm_exec "rm -rf '$server_tmpdir'"
    emit_category_summary "$category" "$pass" "$fail" "$skip"
}
```

### 2.4 Command-Line Interface

```
Usage: ksmbd-torture.sh [OPTIONS]

Test Selection:
  --category CAT[,CAT...]   Run only these categories (T01, T02, B01, ...)
  --test ID[,ID...]          Run only these specific tests (T01.03, T13.17, ...)
  --exclude CAT[,CAT...]     Skip these categories
  --tag TAG[,TAG...]         Run only tests with these tags (slow, quic, smb1)
  --quick                    Run only fast tests (timeout <= 10s, no 'slow' tag)
  --benchmark                Run benchmark categories (B01-B07) instead of tests

Execution:
  --parallel N               Run up to N tests in parallel within a category
  --restart-between          Reload ksmbd module between categories
  --retry N                  Retry failed tests N times before marking FAIL
  --shuffle                  Randomize test order within categories

VM Target:
  --vm NAME                  VM name (VM3, VM4) or HOST:SSHPORT:SMBPORT
  --share NAME               Share name to test against (default: testshare)
  --user USER%PASS           Credentials (default: testuser%testpass)
  --guest                    Connect as guest (no credentials)

Output:
  --json FILE                Write JSON results to FILE (default: results/latest.json)
  --no-color                 Disable color output
  --verbose                  Print full test output, not just PASS/FAIL
  --log FILE                 Write full console log to FILE

Server Control:
  --no-health-check          Skip server health probes between categories
  --no-restart               Never restart server (even if --restart-between is set)

Exit Codes:
  0  All selected tests passed
  1  One or more tests failed
  2  Server crash or unrecoverable error detected
  3  Infrastructure error (VM unreachable, tool missing, config error)
```

### 2.5 JSON Output Format

```json
{
  "suite": "ksmbd-torture",
  "version": "1.0.0",
  "timestamp": "2026-03-02T14:30:00Z",
  "vm": "VM3",
  "server_version": "ksmbd 3.5.3",
  "kernel_version": "6.18.9-arch1-2",
  "duration_ms": 187432,
  "summary": {
    "total": 312,
    "pass": 289,
    "fail": 18,
    "skip": 5,
    "crash": 0
  },
  "categories": [
    {
      "id": "T01",
      "name": "NEGOTIATE",
      "duration_ms": 4521,
      "pass": 12,
      "fail": 0,
      "skip": 1,
      "health": "OK",
      "tests": [
        {
          "id": "T01.01",
          "name": "negotiate_smb2_02_only",
          "status": "PASS",
          "duration_ms": 340,
          "message": ""
        },
        {
          "id": "T01.02",
          "name": "negotiate_smb3_11_only",
          "status": "PASS",
          "duration_ms": 287,
          "message": ""
        }
      ]
    }
  ],
  "health_events": [],
  "benchmarks": []
}
```

### 2.6 Assertion Library (lib/assert.sh)

```bash
# Core assertions -- each sets ASSERT_MSG and returns 0 (pass) or 1 (fail)

assert_status CODE ACTUAL MSG          # Exit code equals expected
assert_eq EXPECTED ACTUAL MSG          # String equality
assert_ne UNEXPECTED ACTUAL MSG        # String inequality
assert_contains HAYSTACK NEEDLE MSG    # Substring match
assert_not_contains HAY NEEDLE MSG     # Substring absence
assert_matches STRING REGEX MSG        # Regex match
assert_file_exists PATH MSG            # File exists on server (via vm_exec)
assert_file_absent PATH MSG            # File does not exist on server
assert_file_size PATH OP SIZE MSG      # File size comparison (-eq, -gt, -lt)
assert_smb_status OUTPUT STATUS MSG    # SMB status code in smbclient output
assert_dmesg_clean SINCE MSG           # No BUG/WARN/OOPS since timestamp
assert_slab_stable BASELINE THRESH MSG # Slab growth within threshold
assert_no_open_fds BASELINE MSG        # No FD leak since baseline
```

### 2.7 SMB Helper Library (lib/smb_helpers.sh)

```bash
# smbclient wrappers with retry logic and structured output capture

smb_ls SHARE PATH                      # List directory, return file list
smb_put SHARE LOCAL REMOTE             # Upload file
smb_get SHARE REMOTE LOCAL             # Download file
smb_mkdir SHARE PATH                   # Create directory
smb_rmdir SHARE PATH                   # Remove directory
smb_rm SHARE PATH                      # Delete file
smb_rename SHARE OLD NEW               # Rename
smb_stat SHARE PATH                    # Get file attributes
smb_deltree SHARE PATH                 # Recursive delete

# smbtorture wrappers with result parsing

torture_run SUITE TEST [OPTS...]       # Run smbtorture test, parse result
torture_run_expect_fail SUITE TEST     # Expect failure (known-bad test)
torture_list SUITE                     # List available tests in suite

# Raw protocol helpers

smb_negotiate_raw DIALECT [OPTS...]    # Send raw negotiate via Python client
smb_compound_raw CMD1 CMD2 [CMD3...]   # Build and send compound request
smb_credit_check SHARE                 # Return current credit grant
```

### 2.8 Server Health Library (lib/server_health.sh)

```bash
# Health probing -- all operations via SSH to the VM

health_snapshot()           # Capture baseline: dmesg position, slab counts, FD count
health_check()              # Compare current state to baseline, return OK or description
health_dmesg_since MARK     # Return new dmesg lines since mark
health_dmesg_errors MARK    # Return only BUG/WARN/OOPS/RCU lines since mark
health_slab_delta BASE      # Return slab object count delta for ksmbd caches
health_fd_count             # Return number of open FDs for ksmbd kernel threads
health_conn_count           # Return active connection count from /proc
health_meminfo_delta BASE   # Return MemFree/Slab/SUnreclaim deltas
health_force_restart        # Emergency: kill daemon, rmmod, insmod, restart
health_wait_ready TIMEOUT   # Wait for ksmbd to accept connections (poll SMB port)
```

### 2.9 VM Control Library (lib/vm_control.sh)

```bash
VM_SSH_CMD="sshpass -p root ssh -o StrictHostKeyChecking=no -p PORT root@127.0.0.1"

vm_exec CMD                # Execute command on VM via SSH, return output + exit code
vm_exec_bg CMD             # Execute in background (for long-running operations)
vm_copy_to LOCAL REMOTE    # scp file to VM
vm_copy_from REMOTE LOCAL  # scp file from VM
vm_reload_ksmbd            # ksmbdctl stop + rmmod ksmbd + insmod ksmbd.ko + ksmbdctl start
vm_is_reachable            # Check SSH + SMB port are up
vm_dmesg_tail N            # Last N lines of dmesg
vm_modprobe_deps           # modprobe lz4, des_generic, etc.
```

### 2.10 Parallel Execution

Within a single category, tests that have no ordering dependencies (`after` field
empty) can run in parallel. The runner uses bash `wait` with PID tracking:

```bash
run_parallel() {
    local max_jobs="$1"; shift
    local pids=()
    local results=()

    for test_id in "$@"; do
        while (( ${#pids[@]} >= max_jobs )); do
            wait -n -p done_pid
            # Collect result from completed job
            collect_result "$done_pid"
            pids=( "${pids[@]/$done_pid}" )
        done

        run_single_test "$test_id" &
        pids+=( $! )
    done

    # Wait for remaining
    for pid in "${pids[@]}"; do
        wait "$pid"
        collect_result "$pid"
    done
}
```

**Safety:** Tests that modify server state (delete-on-close, rename, ACL changes)
are tagged `destructive` and are never parallelized. Only read-only or
self-contained tests run in parallel.


## 3. Test Categories

### Protocol Bootstrap

#### T01_NEGOTIATE -- Protocol Negotiation

**Scope:** SMB2 NEGOTIATE command, dialect selection, negotiate contexts, security
mode, capabilities, server GUID, max transact/read/write sizes.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T01.01  | SMB 2.0.2 only                           | smbclient       | 10s     |
| T01.02  | SMB 2.1 only                             | smbclient       | 10s     |
| T01.03  | SMB 3.0 only                             | smbclient       | 10s     |
| T01.04  | SMB 3.0.2 only                           | smbclient       | 10s     |
| T01.05  | SMB 3.1.1 only                           | smbclient       | 10s     |
| T01.06  | Multi-dialect (2.0.2 through 3.1.1)      | smbclient       | 10s     |
| T01.07  | Highest dialect selected from mixed set   | raw_negotiate.py | 10s    |
| T01.08  | Preauth integrity context (SHA-512)       | raw_negotiate.py | 10s    |
| T01.09  | Encryption context (AES-128-CCM)          | raw_negotiate.py | 10s    |
| T01.10  | Encryption context (AES-128-GCM)          | raw_negotiate.py | 10s    |
| T01.11  | Encryption context (AES-256-CCM)          | raw_negotiate.py | 10s    |
| T01.12  | Encryption context (AES-256-GCM)          | raw_negotiate.py | 10s    |
| T01.13  | Compression context (LZ77, LZNT1, LZ77+Huffman) | raw_negotiate.py | 10s |
| T01.14  | Signing context (AES-CMAC, AES-GMAC, HMAC-SHA256) | raw_negotiate.py | 10s |
| T01.15  | RDMA transform context                   | raw_negotiate.py | 10s    |
| T01.16  | Netname context with valid hostname       | raw_negotiate.py | 10s    |
| T01.17  | Transport capabilities context            | raw_negotiate.py | 10s    |
| T01.18  | Duplicate preauth context rejected        | raw_negotiate.py | 10s    |
| T01.19  | Duplicate encryption context rejected     | raw_negotiate.py | 10s    |
| T01.20  | Zero dialect count rejected               | raw_negotiate.py | 10s    |
| T01.21  | Second NEGOTIATE on same connection rejected | raw_negotiate.py | 10s  |
| T01.22  | Security mode: signing enabled            | smbclient       | 10s     |
| T01.23  | Security mode: signing required           | smbclient       | 10s     |
| T01.24  | Max transact/read/write sizes reported    | raw_negotiate.py | 10s    |
| T01.25  | Server GUID consistency across reconnects | raw_negotiate.py | 15s    |
| T01.26  | Capabilities: large MTU, multichannel, leasing, encryption, directory leasing | raw_negotiate.py | 10s |
| T01.27  | PreAuthHashId missing for 3.1.1 rejected | raw_negotiate.py | 10s    |
| T01.28  | SigningAlgorithmCount=0 rejected          | raw_negotiate.py | 10s    |
| T01.29  | CompressionAlgorithmCount=0 rejected      | raw_negotiate.py | 10s    |
| T01.30  | SMB2_GLOBAL_CAP_NOTIFICATIONS in 3.1.1   | raw_negotiate.py | 10s    |

#### T02_SESSION -- Session Setup & Authentication

**Scope:** NTLMSSP negotiate/auth, Kerberos, guest, anonymous, re-auth, session
binding, encryption, signing enforcement, SESSION_SETUP flags.

| ID      | Test                                          | Method          | Timeout |
|---------|-----------------------------------------------|-----------------|---------|
| T02.01  | NTLMSSP authentication (valid credentials)    | smbclient       | 15s     |
| T02.02  | Invalid password rejected                     | smbclient       | 10s     |
| T02.03  | Invalid username rejected                     | smbclient       | 10s     |
| T02.04  | Guest session (when allowed)                  | smbclient       | 10s     |
| T02.05  | Anonymous session                             | smbclient       | 10s     |
| T02.06  | SESSION_FLAG_IS_NULL set for anonymous        | raw_negotiate.py | 10s    |
| T02.07  | Re-authentication on existing session         | smbtorture      | 15s     |
| T02.08  | Session binding (multichannel)                | smbtorture      | 20s     |
| T02.09  | Session encryption (AES-128-CCM)              | smbclient       | 15s     |
| T02.10  | Session encryption (AES-128-GCM)              | smbclient       | 15s     |
| T02.11  | Signing required + unsigned request rejected  | raw_negotiate.py | 10s    |
| T02.12  | Session logoff cleans up tree connects        | smbclient       | 10s     |
| T02.13  | Session logoff triggers notification          | raw_negotiate.py | 15s    |
| T02.14  | Expired session re-auth                       | smbtorture      | 15s     |
| T02.15  | Max sessions per connection                   | raw_negotiate.py | 30s    |
| T02.16  | Unencrypted request on encrypted session rejected | raw_negotiate.py | 10s |
| T02.17  | ChannelSequence tracking across commands      | raw_negotiate.py | 15s    |
| T02.18  | Pre-auth integrity hash chain validation      | raw_negotiate.py | 15s    |

#### T03_TREE_CONNECT -- Share Access

**Scope:** TREE_CONNECT/DISCONNECT, IPC$ access, share permissions, extension
parsing, path handling, max tree connections.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T03.01  | Connect to regular share                  | smbclient       | 10s     |
| T03.02  | Connect to IPC$                           | smbclient       | 10s     |
| T03.03  | Invalid share name rejected               | smbclient       | 10s     |
| T03.04  | Share name > 80 chars rejected            | raw_negotiate.py | 10s    |
| T03.05  | Tree disconnect                           | smbclient       | 10s     |
| T03.06  | Multiple tree connects to same share      | smbclient       | 10s     |
| T03.07  | Tree connect with extension present flag  | raw_negotiate.py | 10s    |
| T03.08  | Max tree connects per session             | raw_negotiate.py | 30s    |
| T03.09  | Tree connect after session logoff fails   | raw_negotiate.py | 10s    |
| T03.10  | Case-insensitive share name matching      | smbclient       | 10s     |
| T03.11  | Unicode share name (if configured)        | smbclient       | 10s     |
| T03.12  | Share access: read-only share             | smbclient       | 10s     |


### Core File Operations

#### T04_CREATE -- File Create/Open

**Scope:** All create dispositions, access masks, share modes, impersonation
levels, file attributes, security flags, create contexts.

| ID      | Test                                          | Method          | Timeout |
|---------|-----------------------------------------------|-----------------|---------|
| T04.01  | CREATE_NEW -- new file                        | smbclient       | 10s     |
| T04.02  | CREATE_NEW -- existing file rejected          | smbclient       | 10s     |
| T04.03  | OPEN_EXISTING -- existing file                | smbclient       | 10s     |
| T04.04  | OPEN_EXISTING -- nonexistent rejected         | smbclient       | 10s     |
| T04.05  | OPEN_IF -- creates when absent                | smbclient       | 10s     |
| T04.06  | OPEN_IF -- opens when present                 | smbclient       | 10s     |
| T04.07  | OVERWRITE -- existing file truncated          | smbclient       | 10s     |
| T04.08  | OVERWRITE -- nonexistent rejected             | smbclient       | 10s     |
| T04.09  | OVERWRITE_IF -- creates when absent           | smbclient       | 10s     |
| T04.10  | OVERWRITE_IF -- truncates when present        | smbclient       | 10s     |
| T04.11  | SUPERSEDE -- replaces existing file           | smbtorture      | 10s     |
| T04.12  | Access mask: READ_DATA only                   | smbtorture      | 10s     |
| T04.13  | Access mask: WRITE_DATA only                  | smbtorture      | 10s     |
| T04.14  | Access mask: DELETE only                      | smbtorture      | 10s     |
| T04.15  | Access mask: MAXIMUM_ALLOWED                  | smbtorture      | 10s     |
| T04.16  | Access mask: SYNCHRONIZE bit (0xF21F01FF)     | smbtorture      | 10s     |
| T04.17  | Share mode: deny all                          | smbtorture      | 15s     |
| T04.18  | Share mode: allow read                        | smbtorture      | 15s     |
| T04.19  | Share mode: allow write                       | smbtorture      | 15s     |
| T04.20  | Share mode: allow delete                      | smbtorture      | 15s     |
| T04.21  | Impersonation: anonymous                      | smbtorture      | 10s     |
| T04.22  | Impersonation: identification                 | smbtorture      | 10s     |
| T04.23  | Impersonation: impersonation                  | smbtorture      | 10s     |
| T04.24  | File attribute: hidden                        | smbclient       | 10s     |
| T04.25  | File attribute: system                        | smbclient       | 10s     |
| T04.26  | File attribute: readonly                      | smbclient       | 10s     |
| T04.27  | File attribute: archive                       | smbclient       | 10s     |
| T04.28  | Create directory via create                   | smbclient       | 10s     |
| T04.29  | Create context: MxAc (maximum access)         | smbtorture      | 10s     |
| T04.30  | Create context: QFid (query on-disk ID)       | smbtorture      | 10s     |
| T04.31  | Create context: DH2Q (durable v2 request)     | smbtorture      | 15s     |
| T04.32  | Create context: RqLs (request lease)          | smbtorture      | 15s     |
| T04.33  | Create context: AAPL (Apple extensions)       | smbtorture      | 10s     |
| T04.34  | Odd-length NameLength rejected (UTF-16 check) | raw_negotiate.py | 10s   |
| T04.35  | DELETE_ON_CLOSE + readonly rejected           | smbtorture      | 10s     |
| T04.36  | DELETE_ON_CLOSE - daccess without FILE_DELETE  | smbtorture      | 10s    |
| T04.37  | Create with REPARSE_POINT attribute           | smbtorture      | 10s     |
| T04.38  | Open file with extremely long path (> 1024)   | raw_negotiate.py | 10s   |

#### T05_READ -- File Read

**Scope:** Normal reads, EOF behavior, zero-length reads, pipe reads, credit
validation, offset handling.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T05.01  | Read entire small file (1 KB)             | smbclient       | 10s     |
| T05.02  | Read entire medium file (1 MB)            | smbclient       | 15s     |
| T05.03  | Read at exact EOF offset                  | smbtorture      | 10s     |
| T05.04  | Read past EOF (truncated response)        | smbtorture      | 10s     |
| T05.05  | Zero-length read                          | smbtorture      | 10s     |
| T05.06  | Read with offset 0                        | smbclient       | 10s     |
| T05.07  | Read with large offset (> 4 GB)           | smbtorture      | 15s     |
| T05.08  | Read from pipe (IPC$)                     | smbtorture      | 10s     |
| T05.09  | Read with insufficient access rights      | smbtorture      | 10s     |
| T05.10  | Read with credit exhaustion               | credit_exhaust.py | 20s   |
| T05.11  | Sequential multi-read (verify data)       | smbclient       | 15s     |
| T05.12  | READ_UNBUFFERED flag (3.0.2+)            | raw_negotiate.py | 10s    |
| T05.13  | DataOffset validation in response         | raw_negotiate.py | 10s    |

#### T06_WRITE -- File Write

**Scope:** Normal writes, append-to-EOF sentinel, pipe writes, write-through,
offset overflow protection, disk full simulation.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T06.01  | Write small data (1 KB)                   | smbclient       | 10s     |
| T06.02  | Write medium data (1 MB)                  | smbclient       | 15s     |
| T06.03  | Write large data (100 MB)                 | smbclient       | 60s     |
| T06.04  | Append sentinel (offset 0xFFFFFFFFFFFFFFFF) | raw_negotiate.py | 10s  |
| T06.05  | Append to file (FILE_APPEND_DATA access)  | smbtorture      | 10s     |
| T06.06  | Write at non-EOF with append-only access  | smbtorture      | 10s     |
| T06.07  | Write to pipe (IPC$)                      | smbtorture      | 10s     |
| T06.08  | Write-through flag                        | smbtorture      | 10s     |
| T06.09  | Write with insufficient access rights     | smbtorture      | 10s     |
| T06.10  | Write with offset > file size (sparse)    | smbtorture      | 10s     |
| T06.11  | Write offset overflow guard               | raw_negotiate.py | 10s    |
| T06.12  | Verify data integrity after write/read    | smbclient       | 15s     |
| T06.13  | WRITE_UNBUFFERED flag                     | raw_negotiate.py | 10s    |
| T06.14  | Disk full simulation (fill share to quota) | smbclient      | 30s     |

#### T07_CLOSE -- File Close

**Scope:** Normal close, close with delete-on-close, close with pending oplock,
compound close, cleanup behavior.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T07.01  | Normal close                              | smbclient       | 10s     |
| T07.02  | Close with DELETE_ON_CLOSE flag           | smbtorture      | 10s     |
| T07.03  | Close last handle triggers delete         | smbtorture      | 15s     |
| T07.04  | Close non-last handle preserves file      | smbtorture      | 15s     |
| T07.05  | Close with oplock held (no break needed)  | smbtorture      | 15s     |
| T07.06  | Double close (same FID) rejected          | raw_negotiate.py | 10s    |
| T07.07  | Close invalid FID                         | raw_negotiate.py | 10s    |
| T07.08  | Close in compound (CREATE+WRITE+CLOSE)    | smbtorture      | 10s     |

#### T08_FLUSH -- Flush

**Scope:** Flush with proper access, flush without write access, flush on pipe,
compound flush, STATUS_FILE_CLOSED for gone FID.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T08.01  | Flush with WRITE_DATA access              | smbtorture      | 10s     |
| T08.02  | Flush with APPEND_DATA access             | smbtorture      | 10s     |
| T08.03  | Flush without write access rejected       | smbtorture      | 10s     |
| T08.04  | Flush on pipe                             | smbtorture      | 10s     |
| T08.05  | Flush closed FID returns FILE_CLOSED      | raw_negotiate.py | 10s    |
| T08.06  | Flush in compound (CREATE+FLUSH+CLOSE)    | smbtorture      | 10s     |


### Directory & Metadata

#### T09_DIRECTORY -- Directory Enumeration

**Scope:** All FileInformationClass values for QUERY_DIRECTORY, wildcards, restart
scans, large directories, dot/dotdot entries, sorted output.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T09.01  | List directory (FileBothDirectoryInformation) | smbclient    | 10s     |
| T09.02  | List empty directory                      | smbclient       | 10s     |
| T09.03  | List with wildcard "*"                    | smbclient       | 10s     |
| T09.04  | List with wildcard "*.txt"                | smbclient       | 10s     |
| T09.05  | List with wildcard "file?.dat"            | smbclient       | 10s     |
| T09.06  | DOS wildcard "<, >, \"                    | raw_negotiate.py | 10s    |
| T09.07  | Restart scans flag                        | smbtorture      | 10s     |
| T09.08  | Dot and dotdot entries present            | smbtorture      | 10s     |
| T09.09  | Dot/dotdot reset on RESTART_SCANS         | smbtorture      | 10s     |
| T09.10  | Large directory (1,000 files)             | smbclient       | 30s     |
| T09.11  | Large directory (10,000 files)            | smbclient       | 120s    |
| T09.12  | Large directory (100,000 files)           | smbclient       | 300s    |
| T09.13  | FileIdBothDirectoryInformation            | smbtorture      | 10s     |
| T09.14  | FileIdFullDirectoryInformation            | smbtorture      | 10s     |
| T09.15  | FileNamesInformation                      | smbtorture      | 10s     |
| T09.16  | FileDirectoryInformation                  | smbtorture      | 10s     |
| T09.17  | FileFullDirectoryInformation              | smbtorture      | 10s     |
| T09.18  | SingleEntry flag (one result per call)    | raw_negotiate.py | 10s    |
| T09.19  | INDEX_SPECIFIED flag                      | raw_negotiate.py | 10s    |
| T09.20  | REOPEN flag                               | smbtorture      | 10s     |

#### T10_QUERY_INFO -- Query Information

**Scope:** All FileInformationClass values, FS info levels, security descriptor
queries, EA queries.

| ID      | Test                                          | Method          | Timeout |
|---------|-----------------------------------------------|-----------------|---------|
| T10.01  | FileBasicInformation                          | smbtorture      | 10s     |
| T10.02  | FileStandardInformation                       | smbtorture      | 10s     |
| T10.03  | FileInternalInformation                       | smbtorture      | 10s     |
| T10.04  | FileEaInformation                             | smbtorture      | 10s     |
| T10.05  | FileAccessInformation                         | smbtorture      | 10s     |
| T10.06  | FilePositionInformation                       | smbtorture      | 10s     |
| T10.07  | FileModeInformation                           | smbtorture      | 10s     |
| T10.08  | FileAlignmentInformation                      | smbtorture      | 10s     |
| T10.09  | FileAllInformation                            | smbtorture      | 10s     |
| T10.10  | FileNameInformation                           | smbtorture      | 10s     |
| T10.11  | FileNetworkOpenInformation                    | smbtorture      | 10s     |
| T10.12  | FileAttributeTagInformation                   | smbtorture      | 10s     |
| T10.13  | FileStreamInformation (streams)               | smbtorture      | 10s     |
| T10.14  | FileCompressionInformation                    | smbtorture      | 10s     |
| T10.15  | FileStatInformation (0x46)                    | raw_negotiate.py | 10s    |
| T10.16  | FileStatLxInformation (0x47)                  | raw_negotiate.py | 10s    |
| T10.17  | FsInfoVolumeInformation                       | smbclient       | 10s     |
| T10.18  | FsInfoSizeInformation                         | smbclient       | 10s     |
| T10.19  | FsInfoDeviceInformation                       | smbclient       | 10s     |
| T10.20  | FsInfoAttributeInformation                    | smbclient       | 10s     |
| T10.21  | FsInfoFullSizeInformation                     | smbclient       | 10s     |
| T10.22  | FsInfoObjectIdInformation                     | smbclient       | 10s     |
| T10.23  | FsInfoSectorSizeInformation                   | smbclient       | 10s     |
| T10.24  | Security descriptor (DACL)                    | smbtorture      | 10s     |
| T10.25  | Security descriptor (owner SID)               | smbtorture      | 10s     |
| T10.26  | Security descriptor (group SID)               | smbtorture      | 10s     |
| T10.27  | Extended attributes query                     | smbtorture      | 10s     |
| T10.28  | Query on directory                            | smbclient       | 10s     |

#### T11_SET_INFO -- Set Information

**Scope:** Rename, delete disposition, EOF, allocation, timestamps, mode, EA,
security descriptor modification.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T11.01  | Rename file (FileRenameInformation)       | smbclient       | 10s     |
| T11.02  | Rename to existing name (overwrite)       | smbclient       | 10s     |
| T11.03  | Rename across directories                 | smbclient       | 10s     |
| T11.04  | Set delete disposition                    | smbtorture      | 10s     |
| T11.05  | Set EOF (truncate)                        | smbtorture      | 10s     |
| T11.06  | Set EOF (extend)                          | smbtorture      | 10s     |
| T11.07  | Set allocation size                       | smbtorture      | 10s     |
| T11.08  | Set timestamps (create, modify, access)   | smbtorture      | 10s     |
| T11.09  | Set timestamps to epoch (freeze)          | smbtorture      | 10s     |
| T11.10  | Set timestamps to -1 (preserve)           | smbtorture      | 10s     |
| T11.11  | Set file attributes (readonly, hidden)    | smbtorture      | 10s     |
| T11.12  | Set mode information                      | smbtorture      | 10s     |
| T11.13  | Set extended attributes                   | smbtorture      | 10s     |
| T11.14  | Set security descriptor (DACL)            | smbtorture      | 15s     |
| T11.15  | Set security descriptor (owner)           | smbtorture      | 15s     |
| T11.16  | Rename open file with share delete        | smbtorture      | 15s     |

#### T12_TIMESTAMPS -- Timestamp Behavior

**Scope:** Delayed write update semantics, timestamp resolution, freeze/thaw,
epoch boundary handling.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T12.01  | Write updates mtime                       | smbtorture      | 15s     |
| T12.02  | Delayed write update (2-second window)    | smbtorture      | 20s     |
| T12.03  | Timestamp resolution (100ns granularity)  | smbtorture      | 10s     |
| T12.04  | Frozen timestamp on open handle           | smbtorture      | 15s     |
| T12.05  | Thaw timestamp on close                   | smbtorture      | 15s     |
| T12.06  | Epoch value (0) handling                  | smbtorture      | 10s     |
| T12.07  | Set timestamp to max FILETIME             | raw_negotiate.py | 10s    |
| T12.08  | Birth time (create time) preserved        | smbtorture      | 10s     |


### Locking & Concurrency

#### T13_LOCK -- Byte-Range Locking

**Scope:** All lock flag combinations, range arithmetic, zero-byte locks, overlap
detection, lock cancel, rollback, sequence replay (MS-SMB2 3.3.5.14).

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T13.01  | Exclusive lock (entire file)              | smbtorture      | 10s     |
| T13.02  | Shared lock (entire file)                 | smbtorture      | 10s     |
| T13.03  | Exclusive lock blocks exclusive           | smbtorture      | 15s     |
| T13.04  | Exclusive lock blocks shared              | smbtorture      | 15s     |
| T13.05  | Shared lock allows shared                 | smbtorture      | 15s     |
| T13.06  | Shared lock blocks exclusive              | smbtorture      | 15s     |
| T13.07  | Zero-byte lock range                      | smbtorture      | 10s     |
| T13.08  | Lock at OFFSET_MAX boundary               | smbtorture      | 10s     |
| T13.09  | Overlapping lock ranges                   | smbtorture      | 15s     |
| T13.10  | Lock cancel (SMB2_LOCKFLAG_CANCEL)        | smbtorture      | 15s     |
| T13.11  | Lock rollback on partial failure          | smbtorture      | 15s     |
| T13.12  | Lock upgrade (shared to exclusive)        | smbtorture      | 15s     |
| T13.13  | Lock downgrade (exclusive to shared)      | smbtorture      | 15s     |
| T13.14  | Unlock nonexistent lock                   | smbtorture      | 10s     |
| T13.15  | Lock sequence replay (resilient handle)   | raw_negotiate.py | 15s    |
| T13.16  | Lock sequence valid/invalid transitions   | raw_negotiate.py | 15s    |
| T13.17  | Lock sequence bit extraction (low nibble) | raw_negotiate.py | 10s    |
| T13.18  | Same-handle blocking upgrade detection    | smbtorture      | 15s     |
| T13.19  | POSIX fl_end inclusive range verification  | smbtorture      | 10s     |
| T13.20  | Lock on close cleanup (all locks freed)   | smbtorture      | 15s     |
| T13.21  | Cross-connection lock conflict            | smbtorture      | 20s     |
| T13.22  | Multiple lock ranges on same file         | smbtorture      | 15s     |

#### T14_OPLOCK -- Opportunistic Locks

**Scope:** All oplock levels, break timing, batch oplocks, stream oplocks,
cross-connection breaks, directory oplocks.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T14.01  | Level II oplock grant                     | smbtorture      | 15s     |
| T14.02  | Exclusive oplock grant                    | smbtorture      | 15s     |
| T14.03  | Batch oplock grant                        | smbtorture      | 15s     |
| T14.04  | Exclusive-to-Level II break               | smbtorture      | 15s     |
| T14.05  | Exclusive-to-None break                   | smbtorture      | 15s     |
| T14.06  | Batch-to-Level II break                   | smbtorture      | 15s     |
| T14.07  | Break timing (within 35 seconds)          | oplock_break_timer.py | 40s |
| T14.08  | Break acknowledgement                     | smbtorture      | 15s     |
| T14.09  | Break timeout (no ack, force close)       | oplock_break_timer.py | 45s |
| T14.10  | Oplock on alternate stream                | smbtorture      | 15s     |
| T14.11  | Cross-connection oplock conflict          | smbtorture      | 20s     |
| T14.12  | Directory oplock (Level II only)          | smbtorture      | 15s     |
| T14.13  | Oplock break during compound request      | smbtorture      | 20s     |
| T14.14  | None oplock (no caching)                  | smbtorture      | 10s     |
| T14.15  | Oplock preserved across rename            | smbtorture      | 15s     |
| T14.16  | Delegate all smbtorture oplock tests      | smbtorture      | 300s    |

#### T15_LEASE -- Directory and File Leases

**Scope:** Lease V1, V2, directory leases, epoch tracking, parent key, break
timing, upgrade/downgrade transitions.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T15.01  | Read lease grant                          | smbtorture      | 15s     |
| T15.02  | Read-Handle lease grant                   | smbtorture      | 15s     |
| T15.03  | Read-Write lease grant                    | smbtorture      | 15s     |
| T15.04  | Read-Write-Handle lease grant             | smbtorture      | 15s     |
| T15.05  | Lease break RWH to RW                     | smbtorture      | 15s     |
| T15.06  | Lease break RWH to RH                     | smbtorture      | 15s     |
| T15.07  | Lease break RW to R                       | smbtorture      | 15s     |
| T15.08  | Lease break R to None                     | smbtorture      | 15s     |
| T15.09  | Lease V2 with parent key                  | smbtorture      | 15s     |
| T15.10  | Lease V2 epoch tracking                   | smbtorture      | 15s     |
| T15.11  | Directory lease (V2 only)                 | smbtorture      | 15s     |
| T15.12  | Lease upgrade (R to RW)                   | smbtorture      | 15s     |
| T15.13  | Lease downgrade acknowledged              | smbtorture      | 15s     |
| T15.14  | Cross-connection lease conflict           | smbtorture      | 20s     |
| T15.15  | Lease break timing measurement            | oplock_break_timer.py | 40s |
| T15.16  | Delegate all smbtorture lease tests       | smbtorture      | 300s    |

#### T16_SHAREMODE -- Share Mode Enforcement

**Scope:** All deny-read/write/delete combinations, cross-connection share mode
conflicts, share mode inheritance.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T16.01  | Deny read: second reader rejected         | smbtorture      | 15s     |
| T16.02  | Deny write: second writer rejected        | smbtorture      | 15s     |
| T16.03  | Deny delete: rename rejected              | smbtorture      | 15s     |
| T16.04  | Allow all: concurrent access succeeds     | smbtorture      | 15s     |
| T16.05  | Deny none: all access modes pass          | smbtorture      | 15s     |
| T16.06  | Cross-connection share mode conflict      | smbtorture      | 20s     |
| T16.07  | Share mode with oplock interaction        | smbtorture      | 20s     |
| T16.08  | All 9 deny-read/write/delete combos       | smbtorture      | 30s     |


### Compound & Async

#### T17_COMPOUND -- Compound Requests

**Scope:** Related and unrelated compounds, FID propagation from all command
types, error cascade semantics, padding, interim responses.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T17.01  | Related: CREATE + WRITE + CLOSE           | smbtorture      | 10s     |
| T17.02  | Related: CREATE + READ + CLOSE            | smbtorture      | 10s     |
| T17.03  | Related: CREATE + QUERY_INFO + CLOSE      | smbtorture      | 10s     |
| T17.04  | Related: CREATE + SET_INFO + CLOSE        | smbtorture      | 10s     |
| T17.05  | Related: CREATE + FLUSH + CLOSE           | smbtorture      | 10s     |
| T17.06  | Unrelated: independent CREATE + CREATE    | smbtorture      | 10s     |
| T17.07  | FID propagation from FLUSH response       | compound_builder.py | 10s |
| T17.08  | FID propagation from READ response        | compound_builder.py | 10s |
| T17.09  | FID propagation from WRITE response       | compound_builder.py | 10s |
| T17.10  | FID propagation from LOCK response        | compound_builder.py | 10s |
| T17.11  | FID propagation from IOCTL response       | compound_builder.py | 10s |
| T17.12  | FID propagation from QUERY_DIR response   | compound_builder.py | 10s |
| T17.13  | FID propagation from NOTIFY response      | compound_builder.py | 10s |
| T17.14  | Error cascade: CREATE fails, later cmds fail | smbtorture   | 10s     |
| T17.15  | Error cascade: non-CREATE fail, next continues | smbtorture | 10s     |
| T17.16  | 8-byte padding between compound elements  | compound_builder.py | 10s |
| T17.17  | Interim response for async compound       | smbtorture      | 15s     |
| T17.18  | All smbtorture compound tests             | smbtorture      | 120s    |

#### T18_ASYNC -- Asynchronous Operations

**Scope:** CANCEL command, async timeouts, notify completion, lock wait
completion, credit tracking for async operations.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T18.01  | CANCEL pending lock request               | smbtorture      | 15s     |
| T18.02  | CANCEL pending notify request             | smbtorture      | 15s     |
| T18.03  | Async lock wait completion                | smbtorture      | 15s     |
| T18.04  | Async notify completion                   | smbtorture      | 15s     |
| T18.05  | Async credit tracking (no credit leak)    | raw_negotiate.py | 20s    |
| T18.06  | Multiple pending async operations         | raw_negotiate.py | 20s    |
| T18.07  | CANCEL non-existent async ID              | raw_negotiate.py | 10s    |
| T18.08  | CANCEL signing exclusion (MS-SMB2)        | raw_negotiate.py | 10s    |


### IOCTL / FSCTL

#### T19_COPYCHUNK -- Server-Side Copy

**Scope:** Simple copy, multi-chunk, cross-file, cross-share, overlapping,
max chunk count, resume key lifecycle.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T19.01  | Simple single-chunk copy                  | smbtorture      | 15s     |
| T19.02  | Multi-chunk copy                          | smbtorture      | 15s     |
| T19.03  | Cross-file copy (same share)              | smbtorture      | 15s     |
| T19.04  | Overlapping source and target ranges      | smbtorture      | 15s     |
| T19.05  | Max chunk count boundary                  | smbtorture      | 15s     |
| T19.06  | Resume key request (SRV_REQUEST_RESUME_KEY) | smbtorture    | 10s     |
| T19.07  | Invalid resume key rejected               | smbtorture      | 10s     |
| T19.08  | Copy with source at EOF                   | smbtorture      | 10s     |
| T19.09  | Zero-length chunk                         | smbtorture      | 10s     |
| T19.10  | COPYCHUNK_WRITE variant                   | smbtorture      | 15s     |

#### T20_SPARSE -- Sparse File Operations

**Scope:** Set sparse attribute, query allocated ranges, punch hole, set zero data.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T20.01  | Set sparse attribute                      | smbtorture      | 10s     |
| T20.02  | Query allocated ranges (empty file)       | smbtorture      | 10s     |
| T20.03  | Query allocated ranges (partial)          | smbtorture      | 10s     |
| T20.04  | Set zero data (punch hole)                | smbtorture      | 10s     |
| T20.05  | Sparse + allocated range verification     | smbtorture      | 15s     |
| T20.06  | Set sparse with no buffer (default TRUE)  | raw_negotiate.py | 10s    |
| T20.07  | Sparse across large file (> 4 GB)         | smbtorture      | 30s     |

#### T21_INTEGRITY -- Integrity Information

**Scope:** Get/set integrity information, checksum types.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T21.01  | Get integrity information                 | smbtorture      | 10s     |
| T21.02  | Set integrity information                 | smbtorture      | 10s     |
| T21.03  | Checksum type negotiation                 | smbtorture      | 10s     |

#### T22_DEDUPE -- Duplicate Extents

**Scope:** FSCTL_DUPLICATE_EXTENTS, boundary conditions, alignment requirements.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T22.01  | Duplicate extents (simple)                | smbtorture      | 15s     |
| T22.02  | Duplicate extents (boundary alignment)    | smbtorture      | 15s     |
| T22.03  | Duplicate extents (cross-file)            | smbtorture      | 15s     |
| T22.04  | Misaligned offset rejected                | smbtorture      | 10s     |

#### T23_ODX -- Offload Data Transfer

**Scope:** FSCTL_OFFLOAD_READ, FSCTL_OFFLOAD_WRITE, token lifecycle.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T23.01  | Offload read (get token)                  | smbtorture      | 15s     |
| T23.02  | Offload write (use token)                 | smbtorture      | 15s     |
| T23.03  | Token expiry                              | smbtorture      | 30s     |
| T23.04  | Invalid token rejected                    | smbtorture      | 10s     |

#### T24_NETWORK_INFO -- Network Interface Enumeration

**Scope:** FSCTL_QUERY_NETWORK_INTERFACE_INFO, interface list parsing.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T24.01  | Query network interfaces                  | smbtorture      | 10s     |
| T24.02  | Interface capability flags parsed         | smbtorture      | 10s     |
| T24.03  | Multiple interfaces reported              | smbtorture      | 10s     |

#### T25_VALIDATE_NEGOTIATE -- Negotiate Validation

**Scope:** FSCTL_VALIDATE_NEGOTIATE_INFO, dialect mismatch detection, MITM defense.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T25.01  | Valid negotiate info matches               | smbtorture      | 10s     |
| T25.02  | Mismatched dialect triggers disconnect    | raw_negotiate.py | 10s    |
| T25.03  | Mismatched capabilities triggers disconnect | raw_negotiate.py | 10s  |
| T25.04  | Mismatched GUID triggers disconnect       | raw_negotiate.py | 10s    |
| T25.05  | IOCTL Flags=0 rejected (must be FSCTL)   | raw_negotiate.py | 10s    |
| T25.06  | ClientGUID set for all SMB2 dialects (>=2.0.2) | raw_negotiate.py | 10s |


### Change Notification

#### T26_NOTIFY -- Change Notification

**Scope:** All CompletionFilter flags, recursive WATCH_TREE, cancel, buffer
overflow, directory removal while watched.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T26.01  | Notify on file create (FILE_NOTIFY_CHANGE_FILE_NAME) | smbtorture | 15s |
| T26.02  | Notify on file delete                     | smbtorture      | 15s     |
| T26.03  | Notify on file rename                     | smbtorture      | 15s     |
| T26.04  | Notify on directory create                | smbtorture      | 15s     |
| T26.05  | Notify on file write (LAST_WRITE)         | smbtorture      | 15s     |
| T26.06  | Notify on attribute change                | smbtorture      | 15s     |
| T26.07  | Notify on security change                 | smbtorture      | 15s     |
| T26.08  | WATCH_TREE (recursive notification)       | smbtorture      | 20s     |
| T26.09  | Cancel pending notify                     | smbtorture      | 15s     |
| T26.10  | Notify buffer overflow                    | smbtorture      | 15s     |
| T26.11  | Remove watched directory                  | smbtorture      | 15s     |
| T26.12  | Multiple notify registrations             | smbtorture      | 20s     |
| T26.13  | Notify with compound FID                  | compound_builder.py | 15s |
| T26.14  | All filter flags combined                 | smbtorture      | 15s     |


### Durable & Resilient

#### T27_DURABLE_V1 -- Durable Handle V1

**Scope:** Durable open, reconnect, delete-on-close preservation, lock
preservation across reconnect.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T27.01  | Durable open request                      | smbtorture      | 15s     |
| T27.02  | Durable reconnect after disconnect        | smbtorture      | 30s     |
| T27.03  | Durable with delete-on-close              | smbtorture      | 15s     |
| T27.04  | Lock preserved across durable reconnect   | smbtorture      | 30s     |
| T27.05  | Durable timeout expiry                    | smbtorture      | 120s    |
| T27.06  | Durable with oplock                       | smbtorture      | 20s     |
| T27.07  | Durable with lease                        | smbtorture      | 20s     |
| T27.08  | Durable reconnect with wrong client GUID  | smbtorture      | 15s     |
| T27.09  | Delegate all smbtorture durable-open tests | smbtorture     | 300s    |

#### T28_DURABLE_V2 -- Durable Handle V2 / Persistent

**Scope:** Persistent handles, create GUID, timeout, app instance ID, reconnect
twice.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T28.01  | Durable V2 open (non-persistent)          | smbtorture      | 15s     |
| T28.02  | Durable V2 reconnect                      | smbtorture      | 30s     |
| T28.03  | Persistent handle request                 | smbtorture      | 15s     |
| T28.04  | Persistent reconnect                      | smbtorture      | 30s     |
| T28.05  | App instance ID conflict resolution       | smbtorture      | 20s     |
| T28.06  | Durable V2 timeout negotiation            | smbtorture      | 30s     |
| T28.07  | Reconnect twice (same create GUID)        | smbtorture      | 45s     |
| T28.08  | Durable V2 with lease V2                  | smbtorture      | 20s     |
| T28.09  | Delegate all smbtorture durable-v2 tests  | smbtorture      | 300s    |

#### T29_RESILIENT -- Resilient Handles

**Scope:** FSCTL_LMR_REQUEST_RESILIENCY, handle preservation, timeout.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T29.01  | Request resiliency                        | smbtorture      | 15s     |
| T29.02  | Resilient handle survives disconnect      | smbtorture      | 30s     |
| T29.03  | Resilient timeout expiry                  | smbtorture      | 120s    |
| T29.04  | Resilient with lock sequence              | smbtorture      | 20s     |


### Security & ACL

#### T30_ACL -- Access Control Lists

**Scope:** DACL, SACL, inheritance, generic-to-specific mapping, owner SID,
creator owner SID.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T30.01  | Read DACL                                 | smbtorture      | 10s     |
| T30.02  | Set DACL (add ACE)                        | smbtorture      | 15s     |
| T30.03  | DACL deny ACE overrides allow             | smbtorture      | 15s     |
| T30.04  | ACL inheritance from parent directory     | smbtorture      | 15s     |
| T30.05  | Generic mapping (GENERIC_READ -> specific) | smbtorture     | 10s     |
| T30.06  | Owner SID query                           | smbtorture      | 10s     |
| T30.07  | Set owner SID                             | smbtorture      | 15s     |
| T30.08  | Creator-owner SID inheritance             | smbtorture      | 15s     |
| T30.09  | Empty DACL (deny all)                     | smbtorture      | 10s     |
| T30.10  | NULL DACL (allow all)                     | smbtorture      | 10s     |
| T30.11  | SACL query (requires privilege)           | smbtorture      | 10s     |
| T30.12  | Hide-on-access-denied behavior            | smbtorture      | 15s     |
| T30.13  | FILE_READ_ATTRIBUTES vs full deny         | raw_negotiate.py | 15s    |

#### T31_DELETE_ON_CLOSE -- Delete-on-Close Semantics

**Scope:** All delete-on-close edge cases: permissions, readonly, sharing,
overwrite_if, multi-handle coordination.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T31.01  | Delete on close: basic                    | smbtorture      | 10s     |
| T31.02  | Delete on close: readonly file rejected   | smbtorture      | 10s     |
| T31.03  | Delete on close: without FILE_DELETE      | smbtorture      | 10s     |
| T31.04  | Delete on close: sharing violation        | smbtorture      | 15s     |
| T31.05  | Delete on close: last handle triggers     | smbtorture      | 15s     |
| T31.06  | Delete pending blocks new opens           | smbtorture      | 15s     |
| T31.07  | OVERWRITE_IF with delete-on-close         | smbtorture      | 10s     |
| T31.08  | Multi-handle delete-on-close coordination | smbtorture      | 20s     |
| T31.09  | Delegate smbtorture delete-on-close-perms | smbtorture      | 120s    |


### Protocol Extensions (ksmbd-specific)

#### T32_COMPRESSION -- SMB3 Compression

**Scope:** Negotiate compression algorithms, compress/decompress round-trip,
all algorithm variants, chained vs unchained patterns.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T32.01  | Negotiate LZNT1 compression               | raw_negotiate.py | 10s    |
| T32.02  | Negotiate LZ77 compression                | raw_negotiate.py | 10s    |
| T32.03  | Negotiate LZ77+Huffman compression        | raw_negotiate.py | 10s    |
| T32.04  | Compress small payload (< 1 KB)           | raw_negotiate.py | 10s    |
| T32.05  | Compress medium payload (64 KB)           | raw_negotiate.py | 15s    |
| T32.06  | Compress large payload (1 MB)             | raw_negotiate.py | 30s    |
| T32.07  | Decompress server response                | raw_negotiate.py | 15s    |
| T32.08  | Round-trip data integrity check           | raw_negotiate.py | 15s    |
| T32.09  | Chained compression pattern               | raw_negotiate.py | 15s    |
| T32.10  | Unchained compression pattern             | raw_negotiate.py | 15s    |
| T32.11  | Incompressible data (random bytes)        | raw_negotiate.py | 15s    |
| T32.12  | Decompression bomb guard                  | raw_negotiate.py | 10s    |

#### T33_QUIC -- QUIC Transport

**Scope:** QUIC connection establishment, file operations over QUIC, transport
fallback. Requires QUIC-enabled VM4.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T33.01  | QUIC initial handshake                    | quic_probe.py   | 15s     |
| T33.02  | QUIC connection + negotiate               | smbclient       | 15s     |
| T33.03  | QUIC session setup                        | smbclient       | 15s     |
| T33.04  | QUIC file read/write                      | smbclient       | 20s     |
| T33.05  | QUIC large file transfer                  | smbclient       | 60s     |
| T33.06  | QUIC connection resume                    | quic_probe.py   | 20s     |
| T33.07  | QUIC + encryption layering                | smbclient       | 15s     |

#### T34_FRUIT -- Apple Extensions

**Scope:** AAPL create context, Time Machine, Finder info, resource fork,
AFP_AfpInfo stream.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T34.01  | AAPL create context negotiation           | smbtorture      | 10s     |
| T34.02  | Resource fork read/write                  | smbclient       | 15s     |
| T34.03  | AFP_AfpInfo stream                        | smbclient       | 15s     |
| T34.04  | Finder info metadata                      | smbclient       | 10s     |
| T34.05  | Time Machine compatibility mode           | smbclient       | 15s     |
| T34.06  | Netatalk compatibility                    | smbtorture      | 15s     |

#### T35_DFS -- Distributed File System

**Scope:** DFS referral request, path resolution, DFS-aware tree connect.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T35.01  | DFS referral request (FSCTL)              | smbtorture      | 10s     |
| T35.02  | DFS path resolution                       | smbtorture      | 15s     |
| T35.03  | DFS-aware tree connect flag               | raw_negotiate.py | 10s    |
| T35.04  | Invalid DFS path                          | smbtorture      | 10s     |

#### T36_VSS -- Volume Shadow Copy

**Scope:** Snapshot enumeration, timewarp open, read-only enforcement on
snapshot files.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T36.01  | Enumerate snapshots (FSCTL)               | smbtorture      | 15s     |
| T36.02  | Timewarp create context                   | smbtorture      | 15s     |
| T36.03  | Snapshot file is read-only                | smbtorture      | 15s     |
| T36.04  | Snapshot directory listing                | smbtorture      | 15s     |

#### T37_NOTIFY_EXTENDED -- Server-to-Client Notifications

**Scope:** SMB2_SERVER_TO_CLIENT_NOTIFICATION (command 0x0013), session closed
notification, multi-channel notification fan-out.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T37.01  | Session closed notification received      | raw_negotiate.py | 20s    |
| T37.02  | Notification only on 3.1.1 connections    | raw_negotiate.py | 15s    |
| T37.03  | Notification sent to all channels         | raw_negotiate.py | 20s    |
| T37.04  | No notification for self-logoff           | raw_negotiate.py | 15s    |


### Streams & Named Pipes

#### T38_STREAMS -- Alternate Data Streams

**Scope:** Create, read/write, rename, delete, share modes, zero-byte streams,
stream attributes.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T38.01  | Create alternate stream                   | smbtorture      | 10s     |
| T38.02  | Read/write alternate stream               | smbtorture      | 10s     |
| T38.03  | List streams (FileStreamInformation)      | smbtorture      | 10s     |
| T38.04  | Delete alternate stream                   | smbtorture      | 10s     |
| T38.05  | Rename alternate stream                   | smbtorture      | 10s     |
| T38.06  | Zero-byte stream                          | smbtorture      | 10s     |
| T38.07  | Stream share modes                        | smbtorture      | 15s     |
| T38.08  | Delete base file deletes all streams      | smbtorture      | 10s     |
| T38.09  | Default stream (:$DATA)                   | smbtorture      | 10s     |
| T38.10  | Delegate all smbtorture streams tests     | smbtorture      | 120s    |

#### T39_PIPES -- Named Pipes (IPC$)

**Scope:** IPC$ tree connect, pipe read/write, transact, DCE/RPC, named pipe
wait.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T39.01  | Open named pipe (\\srvsvc)                | smbclient       | 10s     |
| T39.02  | Pipe transact (RPC call)                  | smbclient       | 10s     |
| T39.03  | NetShareEnum via RPC                      | smbclient       | 10s     |
| T39.04  | NetServerGetInfo via RPC                  | smbclient       | 10s     |
| T39.05  | Pipe read without data ready              | raw_negotiate.py | 10s    |
| T39.06  | Pipe write then read                      | raw_negotiate.py | 10s    |
| T39.07  | FSCTL_PIPE_PEEK                           | raw_negotiate.py | 10s    |
| T39.08  | FSCTL_PIPE_WAIT                           | raw_negotiate.py | 15s    |
| T39.09  | Multiple concurrent pipe operations       | raw_negotiate.py | 15s    |


### SMB1 (Legacy)

#### T40_SMB1_NEGOTIATE -- SMB1 Dialect Negotiation

**Scope:** SMB1 dialect matching, upgrade path to SMB2.

| ID      | Test                                          | Method          | Timeout |
|---------|-----------------------------------------------|-----------------|---------|
| T40.01  | SMB1 "NT LM 0.12" dialect match              | smbclient       | 10s     |
| T40.02  | SMB1 "NT LANMAN 1.0" alias match             | raw_negotiate.py | 10s    |
| T40.03  | SMB1 to SMB2 upgrade (wildcard 0x02FF)        | raw_negotiate.py | 10s    |
| T40.04  | SMB1-only connection (no upgrade)             | smbclient       | 10s     |
| T40.05  | SMB1 deprecation warning in dmesg             | smbclient       | 10s     |
| T40.06  | Unknown SMB1 dialect rejected                 | raw_negotiate.py | 10s    |

#### T41_SMB1_SESSION -- SMB1 Session Operations

**Scope:** SESSION_SETUP_ANDX, TREE_CONNECT_ANDX, TREE_DISCONNECT, LOGOFF_ANDX.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T41.01  | SMB1 session setup (valid credentials)    | smbclient       | 15s     |
| T41.02  | SMB1 session setup (invalid password)     | smbclient       | 10s     |
| T41.03  | SMB1 tree connect                         | smbclient       | 10s     |
| T41.04  | SMB1 tree disconnect                      | smbclient       | 10s     |
| T41.05  | SMB1 logoff                               | smbclient       | 10s     |

#### T42_SMB1_FILE_OPS -- SMB1 File Operations

**Scope:** SMB_COM_OPEN_ANDX, READ_ANDX, WRITE_ANDX, CLOSE, RENAME, DELETE,
LOCKING_ANDX.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T42.01  | SMB1 file create + write + read + close   | smbclient       | 15s     |
| T42.02  | SMB1 rename                               | smbclient       | 10s     |
| T42.03  | SMB1 delete                               | smbclient       | 10s     |
| T42.04  | SMB1 directory create + list              | smbclient       | 10s     |
| T42.05  | SMB1 exclusive lock                       | smbclient       | 15s     |
| T42.06  | SMB1 shared lock                          | smbclient       | 15s     |
| T42.07  | SMB1 large file (> 4 GB with LARGE_READX) | smbclient      | 30s     |

#### T43_SMB1_TRANS -- SMB1 Transaction Subcommands

**Scope:** TRANS2, NT_TRANSACT subcommands (IOCTL, NOTIFY_CHANGE, RENAME, QUOTA,
CREATE).

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T43.01  | TRANS2_FIND_FIRST2 (directory listing)    | smbclient       | 10s     |
| T43.02  | TRANS2_QUERY_PATH_INFORMATION             | smbclient       | 10s     |
| T43.03  | TRANS2_SET_PATH_INFORMATION               | smbclient       | 10s     |
| T43.04  | TRANS2_QUERY_FS_INFORMATION               | smbclient       | 10s     |
| T43.05  | NT_TRANSACT_IOCTL                         | smbtorture      | 10s     |
| T43.06  | NT_TRANSACT_NOTIFY_CHANGE                 | smbtorture      | 15s     |
| T43.07  | NT_TRANSACT_RENAME                        | smbtorture      | 10s     |
| T43.08  | NT_TRANSACT_QUERY_SECURITY_DESC           | smbtorture      | 10s     |
| T43.09  | NT_TRANSACT_CREATE (extended)             | smbtorture      | 10s     |


### Credits & Resource Management

#### T44_CREDITS -- Credit Management

**Scope:** Credit granting, credit exhaustion, async credits, max credit cap,
credit tracking across compound operations.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T44.01  | Initial credit grant after negotiate      | raw_negotiate.py | 10s    |
| T44.02  | Credit request/response tracking          | raw_negotiate.py | 15s    |
| T44.03  | Credit exhaustion (0 credits remaining)   | credit_exhaust.py | 30s   |
| T44.04  | Async credit return                       | raw_negotiate.py | 15s    |
| T44.05  | Max credits cap (configurable)            | credit_exhaust.py | 20s   |
| T44.06  | CreditCharge for large I/O (> 64 KB)     | raw_negotiate.py | 15s    |
| T44.07  | Credit underflow for SMB 2.0.2 (no LARGE_MTU) | raw_negotiate.py | 10s |
| T44.08  | Credits in compound requests              | compound_builder.py | 15s |

#### T45_MAXFID -- File Descriptor Limits

**Scope:** Maximum concurrent file handles, resource cleanup, FD exhaustion
recovery.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T45.01  | Open 100 files simultaneously             | raw_negotiate.py | 30s    |
| T45.02  | Open 1,000 files simultaneously           | raw_negotiate.py | 60s    |
| T45.03  | Open 10,000 files simultaneously          | raw_negotiate.py | 120s   |
| T45.04  | FD exhaustion returns proper error        | raw_negotiate.py | 60s    |
| T45.05  | Cleanup after disconnect frees all FDs    | raw_negotiate.py | 30s    |
| T45.06  | FD leak detection (open-close cycle)      | fid_leak.c      | 60s     |


### Stress & Regression

#### T46_CONCURRENT -- Parallel Session Stress

**Scope:** Multiple parallel sessions, contention on shared files, mixed
operation types, cross-session interference.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T46.01  | 10 parallel sessions, independent files   | parallel bash   | 60s     |
| T46.02  | 10 parallel sessions, shared file read    | parallel bash   | 60s     |
| T46.03  | 10 parallel sessions, shared file write   | parallel bash   | 60s     |
| T46.04  | Mixed operations (read/write/lock/notify) | parallel bash   | 120s    |
| T46.05  | Cross-session lock contention             | parallel bash   | 60s     |
| T46.06  | 50 parallel sessions                      | parallel bash   | 120s    |
| T46.07  | 100 parallel sessions                     | parallel bash   | 180s    |

#### T47_RECONNECT -- Connection Stability

**Scope:** Rapid connect/disconnect, session reconnect, transport resilience.

| ID      | Test                                      | Method          | Timeout |
|---------|-------------------------------------------|-----------------|---------|
| T47.01  | 100 rapid connect/disconnect cycles       | reconnect_storm.c | 60s   |
| T47.02  | 1,000 rapid connect/disconnect cycles     | reconnect_storm.c | 180s  |
| T47.03  | Reconnect with pending operations         | reconnect_storm.c | 60s   |
| T47.04  | Reconnect during oplock break             | smbtorture      | 30s     |
| T47.05  | Half-open connection cleanup              | reconnect_storm.c | 60s   |
| T47.06  | Connection timeout enforcement            | raw_negotiate.py | 120s   |

#### T48_RESOURCE_LEAK -- Memory and FD Leak Detection

**Scope:** Slab tracking, meminfo monitoring, FD accounting over sustained
operation.

| ID      | Test                                      | Method            | Timeout |
|---------|-------------------------------------------|-------------------|---------|
| T48.01  | 10,000 open/close cycles, check slab      | script + health   | 300s    |
| T48.02  | 10,000 read/write cycles, check meminfo   | script + health   | 300s    |
| T48.03  | 1,000 session setup/logoff, check slab    | script + health   | 300s    |
| T48.04  | 1,000 tree connect/disconnect, check slab | script + health   | 300s    |
| T48.05  | Sustained mixed workload (30 min)         | script + health   | 1800s   |
| T48.06  | Post-storm FD count returns to baseline   | reconnect_storm.c | 120s   |

#### T49_REGRESSION -- Known-Bug Reproduction

**Scope:** Every bug fixed in MEMORY.md gets a dedicated regression test to
prevent re-introduction. Each test reproduces the exact conditions that triggered
the original bug.

| ID      | Test                                          | Bug Reference       | Timeout |
|---------|-----------------------------------------------|---------------------|---------|
| T49.01  | SMB 2.0.2 credit underflow                   | Session 2026-02-28  | 10s     |
| T49.02  | SMB 2.0.2 validate negotiate ClientGUID       | Session 2026-02-28  | 10s     |
| T49.03  | SMB1 "NT LANMAN 1.0" dialect match           | Session 2026-02-28  | 10s     |
| T49.04  | SMB1 rejected after negotiate (need_neg)      | Session 2026-02-28  | 10s     |
| T49.05  | SMB1 upgrade wildcard dialect 0x02FF          | Session 2026-02-28  | 10s     |
| T49.06  | conn->vals memory leak in re-negotiate        | Session 2026-02-28  | 10s     |
| T49.07  | Lock fl_end off-by-one (inclusive end)        | Session 2026-03-01a | 10s     |
| T49.08  | Lock OFFSET_MAX skip                          | Session 2026-03-01a | 10s     |
| T49.09  | Lock overlap with wrap-around                 | Session 2026-03-01a | 10s     |
| T49.10  | Lock POSIX remove before fput                 | Session 2026-03-01a | 10s     |
| T49.11  | Lock same-handle blocking upgrade             | Session 2026-03-01a | 10s     |
| T49.12  | Compound error cascade (CREATE-only)          | Session 2026-03-01a | 10s     |
| T49.13  | Compound FID in WRITE/NOTIFY                  | Session 2026-03-01a | 10s     |
| T49.14  | Credit notify cancel for piggyback watches    | Session 2026-03-01a | 10s     |
| T49.15  | DESIRED_ACCESS_MASK with SYNCHRONIZE          | Session 2026-03-01b | 10s     |
| T49.16  | Anonymous re-auth (zero-length NtChallenge)   | Session 2026-03-01b | 10s     |
| T49.17  | dot_dotdot reset on RESTART_SCANS             | Session 2026-03-01b | 10s     |
| T49.18  | Delete-on-close non-last-closer no unlink     | Session 2026-03-01b | 15s     |
| T49.19  | Lock sequence bit extraction reversed         | Session 2026-03-01c | 10s     |
| T49.20  | Lock sequence replay returns OK (not EAGAIN)  | Session 2026-03-01c | 10s     |
| T49.21  | Lock sequence array bounds (65 not 16)        | Session 2026-03-01c | 10s     |
| T49.22  | Lock sequence 0xFF sentinel init              | Session 2026-03-01c | 10s     |
| T49.23  | Lock sequence stored after success only       | Session 2026-03-01c | 10s     |
| T49.24  | Second NEGOTIATE rejected                     | Session 2026-03-01d | 10s     |
| T49.25  | Duplicate negotiate contexts rejected         | Session 2026-03-01d | 10s     |
| T49.26  | IOCTL Flags=0 rejected                        | Session 2026-03-01d | 10s     |
| T49.27  | FILE_DELETE_ON_CLOSE without FILE_DELETE       | Session 2026-03-01d | 10s     |
| T49.28  | FILE_APPEND_DATA rejects non-EOF writes       | Session 2026-03-01d | 10s     |
| T49.29  | Odd NameLength rejected (UTF-16 check)        | Session 2026-03-01d | 10s     |
| T49.30  | Share name >= 80 chars rejected               | Session 2026-03-01d | 10s     |
| T49.31  | Session encryption enforcement                | Session 2026-03-01e | 10s     |
| T49.32  | ChannelSequence stale rejected                | Session 2026-03-01e | 10s     |
| T49.33  | WRITE 0xFFFFFFFFFFFFFFFF append sentinel      | Session 2026-03-01g | 10s     |
| T49.34  | SigningAlgorithmCount=0 rejected              | Session 2026-03-01g | 10s     |
| T49.35  | CompressionAlgorithmCount=0 rejected          | Session 2026-03-01g | 10s     |
| T49.36  | No signing overlap fallback to AES-CMAC       | Session 2026-03-01g | 10s     |
| T49.37  | FLUSH without write access rejected           | Session 2026-03-01g | 10s     |
| T49.38  | FLUSH closed FID returns FILE_CLOSED          | Session 2026-03-01g | 10s     |
| T49.39  | Compound FID from non-CREATE commands         | Session 2026-03-02  | 10s     |
| T49.40  | FSCTL_SET_SPARSE no-buffer defaults to TRUE   | Session 2026-03-02  | 10s     |
| T49.41  | DELETE_ON_CLOSE + READONLY = CANNOT_DELETE     | Session 2026-03-02  | 10s     |
| T49.42  | Notification to non-self channels only        | Session 2026-03-01f | 15s     |
| T49.43  | Tree connect extension path offset parsing    | Session 2026-03-01f | 10s     |


### Benchmarks

#### B01_THROUGHPUT -- Raw Throughput

**Scope:** Sequential and random read/write throughput at various block sizes,
measured with fio over SMB.

| ID      | Test                                      | Block Sizes       | Timeout |
|---------|-------------------------------------------|-------------------|---------|
| B01.01  | Sequential read throughput                | 4K,64K,1M,8M      | 120s    |
| B01.02  | Sequential write throughput               | 4K,64K,1M,8M      | 120s    |
| B01.03  | Random read throughput (4K)               | 4K                 | 120s    |
| B01.04  | Random write throughput (4K)              | 4K                 | 120s    |
| B01.05  | Mixed random read/write (70/30)           | 4K                 | 120s    |
| B01.06  | Large sequential read (1 GB file)         | 1M                 | 180s    |
| B01.07  | Large sequential write (1 GB file)        | 1M                 | 180s    |

#### B02_LATENCY -- Per-Operation Latency

**Scope:** Individual SMB2 command latency profiling, P50/P95/P99 percentiles.

| ID      | Test                                      | Operations        | Timeout |
|---------|-------------------------------------------|-------------------|---------|
| B02.01  | CREATE latency (1,000 iterations)         | CREATE+CLOSE       | 60s     |
| B02.02  | READ latency (1,000 x 4KB reads)          | READ              | 60s     |
| B02.03  | WRITE latency (1,000 x 4KB writes)        | WRITE             | 60s     |
| B02.04  | QUERY_INFO latency (1,000 iterations)     | QUERY_INFO        | 60s     |
| B02.05  | SET_INFO latency (1,000 iterations)       | SET_INFO          | 60s     |
| B02.06  | LOCK/UNLOCK latency (1,000 iterations)    | LOCK+UNLOCK       | 60s     |
| B02.07  | Compound (CREATE+WRITE+CLOSE) latency     | Compound          | 60s     |

#### B03_METADATA -- Metadata Operation Rate

**Scope:** File create/delete/stat rate, directory listing throughput.

| ID      | Test                                      | Count             | Timeout |
|---------|-------------------------------------------|-------------------|---------|
| B03.01  | File create rate (10,000 files)           | 10,000             | 120s    |
| B03.02  | File delete rate (10,000 files)           | 10,000             | 120s    |
| B03.03  | File stat rate (10,000 files)             | 10,000             | 120s    |
| B03.04  | Directory listing rate (1,000 entries)    | 1,000              | 60s     |
| B03.05  | Rename rate (10,000 files)                | 10,000             | 120s    |
| B03.06  | Mixed metadata (create+stat+delete)       | 10,000             | 180s    |

#### B04_SCALABILITY -- Client Scaling

**Scope:** Throughput as a function of concurrent client count (1, 2, 4, 8, 16,
32, 64, 128, 256).

| ID      | Test                                      | Clients           | Timeout |
|---------|-------------------------------------------|-------------------|---------|
| B04.01  | Sequential read scaling curve             | 1-256              | 600s    |
| B04.02  | Sequential write scaling curve            | 1-256              | 600s    |
| B04.03  | Random read scaling curve                 | 1-256              | 600s    |
| B04.04  | Metadata operation scaling curve          | 1-256              | 600s    |
| B04.05  | Mixed workload scaling curve              | 1-256              | 600s    |

#### B05_SIGNING_OVERHEAD -- Signing Cost

**Scope:** Throughput comparison: signed vs unsigned for each dialect.

| ID      | Test                                      | Dialects          | Timeout |
|---------|-------------------------------------------|-------------------|---------|
| B05.01  | Sequential read: signed vs unsigned       | 2.1, 3.0, 3.1.1   | 180s    |
| B05.02  | Sequential write: signed vs unsigned      | 2.1, 3.0, 3.1.1   | 180s    |
| B05.03  | Metadata ops: signed vs unsigned          | 2.1, 3.0, 3.1.1   | 180s    |

#### B06_ENCRYPTION_OVERHEAD -- Encryption Cost

**Scope:** Throughput comparison: encrypted vs plaintext.

| ID      | Test                                      | Algorithms        | Timeout |
|---------|-------------------------------------------|-------------------|---------|
| B06.01  | Sequential read: encrypted vs plain       | CCM, GCM          | 180s    |
| B06.02  | Sequential write: encrypted vs plain      | CCM, GCM          | 180s    |
| B06.03  | Metadata ops: encrypted vs plain          | CCM, GCM          | 180s    |
| B06.04  | CCM vs GCM throughput comparison          | CCM vs GCM        | 180s    |

#### B07_COMPRESSION_OVERHEAD -- Compression Cost

**Scope:** Throughput comparison: compressed vs uncompressed, by algorithm.

| ID      | Test                                      | Algorithms         | Timeout |
|---------|-------------------------------------------|--------------------|---------|
| B07.01  | Read: compressed vs uncompressed          | LZNT1,LZ77,LZ77+H | 180s    |
| B07.02  | Write: compressed vs uncompressed         | LZNT1,LZ77,LZ77+H | 180s    |
| B07.03  | Compression ratio by data type            | Text, binary, rand | 120s    |
| B07.04  | CPU overhead measurement (server side)    | All algorithms     | 180s    |


## 4. Implementation Phases

### Phase 1: Framework + Core Operations (T01-T08, B01-B03)

**Estimated effort:** 2 weeks
**Test count:** ~130 tests + 20 benchmarks

**Deliverables:**
1. `ksmbd-torture.sh` main entry point with full CLI parsing
2. `lib/test_framework.sh` -- test registration, sequential/parallel execution,
   result collection, JSON and human-readable output
3. `lib/smb_helpers.sh` -- smbclient wrappers (ls, put, get, mkdir, rm, rename,
   stat, deltree), smbtorture wrapper with result parsing
4. `lib/server_health.sh` -- dmesg monitoring, slab baseline/delta, FD count,
   connection count, crash detection
5. `lib/vm_control.sh` -- SSH exec, module reload, daemon restart, reachability
   check
6. `lib/assert.sh` -- all assertion functions
7. `lib/json_output.sh` -- JSON emitter
8. `lib/benchmark.sh` -- fio SMB integration, latency measurement
9. `categories/T01_negotiate.sh` through `T08_flush.sh` -- all protocol bootstrap
   and core file operation tests
10. `categories/B01_throughput.sh` through `B03_metadata.sh` -- basic benchmarks
11. `clients/raw_negotiate.py` -- raw SMB2 NEGOTIATE with configurable dialects
    and contexts

**Validation gate:** All T01-T08 tests pass against VM3. B01-B03 produce valid
throughput numbers. JSON output parses cleanly. Health monitoring detects
intentionally injected dmesg warnings.

### Phase 2: Directory, Locking, Oplock/Lease (T09-T16)

**Estimated effort:** 2 weeks
**Test count:** ~130 tests

**Deliverables:**
1. `categories/T09_directory.sh` through `T16_sharemode.sh`
2. `clients/oplock_break_timer.py` -- oplock/lease break latency measurement
3. `clients/credit_exhaust.py` -- credit exhaustion testing
4. Enhanced `smb_helpers.sh` with lock, oplock, and lease helper functions

**Validation gate:** T09-T12 pass for all info levels. T13 lock tests all pass
(includes lock sequence replay regression). T14-T15 delegate to smbtorture and
verify pass counts match baseline. T16 share mode matrix fully exercised.

### Phase 3: Compound, IOCTL, Durable, ACL (T17-T31)

**Estimated effort:** 3 weeks
**Test count:** ~160 tests

**Deliverables:**
1. `categories/T17_compound.sh` through `T31_delete_on_close.sh`
2. `clients/compound_builder.py` -- arbitrary compound request construction
3. Enhanced `server_health.sh` with per-operation slab tracking

**Validation gate:** T17 compound tests all pass (including non-CREATE FID
propagation). T19 copychunk validates data integrity. T27-T29 durable/resilient
tests demonstrate reconnect works. T30 ACL tests verify inheritance.

### Phase 4: Extensions, SMB1, Stress, Regression (T32-T49, B04-B07)

**Estimated effort:** 3 weeks
**Test count:** ~180 tests + 15 benchmarks

**Deliverables:**
1. `categories/T32_compression.sh` through `T49_regression.sh`
2. `categories/B04_scalability.sh` through `B07_compression.sh`
3. `clients/quic_probe.py` -- QUIC initial handshake verification
4. `clients/fid_leak.c` -- FD leak stress tool (C, compiled on VM)
5. `clients/reconnect_storm.c` -- rapid connect/disconnect (C, compiled on VM)
6. All 43 regression tests from MEMORY.md bug fixes

**Validation gate:** T40-T43 SMB1 tests pass with deprecation warning in dmesg.
T46-T48 stress tests run for configured duration without crash. T49 regression
tests all pass (100% -- these are non-negotiable). B04 scaling curve shows
expected throughput shape. B05-B07 overhead measurements are consistent across
runs.


## 5. Relationship to smbtorture

### 5.1 What We Delegate to smbtorture

smbtorture (from Samba's test suite) has mature, well-debugged test
implementations for many SMB2 operations. Rather than reimplementing these, we
invoke smbtorture directly and parse its results.

**Delegated test suites:**

| smbtorture Suite        | Our Categories    | Approx. Tests |
|-------------------------|-------------------|---------------|
| smb2.oplock             | T14_OPLOCK        | ~42           |
| smb2.lease              | T15_LEASE         | ~27           |
| smb2.compound           | T17_COMPOUND      | ~20           |
| smb2.durable-open       | T27_DURABLE_V1    | ~26           |
| smb2.durable-v2-open    | T28_DURABLE_V2    | ~33           |
| smb2.lock               | T13_LOCK          | ~22           |
| smb2.create             | T04_CREATE        | ~18           |
| smb2.getinfo            | T10_QUERY_INFO    | ~8            |
| smb2.streams            | T38_STREAMS       | ~14           |
| smb2.notify             | T26_NOTIFY        | ~18           |
| smb2.session            | T02_SESSION       | ~71           |
| smb2.delete-on-close-perms | T31_DELETE_ON_CLOSE | ~9       |

**Integration pattern:**

```bash
# In T14_OPLOCK, test T14.16 delegates all smbtorture oplock tests:
torture_run "smb2" "oplock" \
    --option="torture:server=${VM_HOST}" \
    --option="torture:share=${SHARE_NAME}" \
    -U "${CREDENTIALS}"
```

The `torture_run` wrapper:
1. Invokes smbtorture with the specified suite and test
2. Captures stdout/stderr
3. Parses the result line ("success" / "failure" / "skip")
4. Extracts per-subtest pass/fail counts
5. Maps each smbtorture subtest to our test ID namespace
6. Records wall-clock timing
7. On failure, captures the relevant assertion message for the JSON output

### 5.2 What We Add Beyond smbtorture

ksmbd-torture adds the following capabilities that smbtorture lacks:

**a) ksmbd-specific feature tests (T32-T37)**

smbtorture does not test ksmbd's compression implementation (LZNT1/LZ77/LZ77+Huffman
from scratch), QUIC transport, Apple (Fruit) extensions, or the server-to-client
notification mechanism. These are all custom implementations that need dedicated
test coverage.

**b) Server health monitoring**

smbtorture treats the server as a black box. If a test passes but the server
leaks 50 MB of slab memory, smbtorture will never notice. ksmbd-torture monitors:

- **dmesg** for BUG, WARN, OOPS, RCU stall, refcount saturation, use-after-free
- **slab stats** (`/proc/slabinfo`) for ksmbd-specific cache growth (ksmbd_file_cache,
  ksmbd_work_cache, ksmbd_session_cache, ksmbd_tree_connect_cache)
- **meminfo** for SUnreclaim growth indicating kernel memory leaks
- **open FD count** for ksmbd kernel threads
- **connection count** via `/proc` to verify all connections are cleaned up

A test that "passes" but causes a 10% slab growth is marked as a WARN in the
results, and a test that triggers a BUG or OOPS is an immediate CRASH regardless
of the test's own assertion result.

**c) Edge cases from source analysis (501 cases)**

Source-level analysis of ksmbd identified 501 edge cases not covered by
smbtorture's test suite. These fall into several categories:

1. **Boundary values:** OFFSET_MAX lock ranges, 0xFFFFFFFFFFFFFFFF write offset,
   maximum credit charge, max share name length (80 chars), odd UTF-16 name
   lengths
2. **Error path validation:** What error code is returned for each invalid input?
   smbtorture generally tests happy paths; we test every documented error response
3. **State machine transitions:** Double negotiate, negotiate after session setup,
   tree connect after logoff, operations on expired sessions
4. **Concurrency:** Cross-connection lock conflicts, oplock breaks during compound
   requests, notify with concurrent modifications
5. **Cleanup verification:** FD leak after abnormal disconnect, slab cleanup after
   session timeout, connection state after transport error

**d) Benchmarks**

smbtorture's `bench` suite provides only basic throughput measurement (read/write
at one block size). ksmbd-torture adds:

- **Comprehensive block size matrix** (4K through 8M)
- **Latency percentiles** (P50/P95/P99, not just average)
- **Scaling curves** (1-256 concurrent clients)
- **Security overhead measurement** (signing, encryption, compression)
- **Server-side resource monitoring** during benchmarks (CPU, memory via SSH)
- **Reproducible methodology** (configurable warmup, iterations, cooldown)

**e) Regression test suite (T49)**

Every bug fixed in MEMORY.md (43 bugs at time of writing) gets a dedicated
regression test. These tests reproduce the EXACT conditions that triggered the
original bug:

- Specific protocol dialect
- Specific sequence of SMB commands
- Specific field values (e.g., lock sequence bits, NameLength parity)
- Server state verification (dmesg for the specific fix)

This ensures that refactoring, optimization, or new feature work does not
re-introduce previously fixed bugs. The regression suite is run as part of every
CI build.

### 5.3 Compatibility Matrix

| Capability                      | smbtorture | ksmbd-torture |
|---------------------------------|:----------:|:-------------:|
| SMB2 command coverage           | Good       | Comprehensive |
| SMB1 coverage                   | Minimal    | Full          |
| Negotiate context testing       | Basic      | Exhaustive    |
| Server health monitoring        | None       | Full          |
| Crash detection                 | None       | Automatic     |
| Resource leak detection         | None       | Slab/FD/mem   |
| Benchmark suite                 | Basic      | Full          |
| ksmbd compression               | None       | Full          |
| ksmbd QUIC transport            | None       | Full          |
| Apple/Fruit extensions          | Basic      | Full          |
| Server-to-client notifications  | None       | Full          |
| Regression suite                | None       | 43+ tests     |
| JSON CI output                  | No         | Yes           |
| Parallel execution              | No         | Yes           |
| Automatic server restart        | No         | Yes           |
| Per-test timeout                | Global     | Per-test      |


## 6. Test Data and Fixture Management

### 6.1 Test Data Files

Tests require various fixture files. These are stored in `fixtures/` and
deployed to the VM share at the start of each run:

| Fixture                         | Size    | Purpose                              |
|---------------------------------|---------|--------------------------------------|
| `small.dat`                     | 1 KB    | Basic read/write verification        |
| `medium.dat`                    | 1 MB    | Medium transfer tests                |
| `large.dat`                     | 100 MB  | Large transfer / throughput tests    |
| `huge.dat`                      | 1 GB    | Benchmark file (generated, not stored) |
| `pattern.dat`                   | 64 KB   | Known byte pattern for integrity     |
| `acl_templates/*.bin`           | Various | Pre-built security descriptors       |
| `ea_data/*.bin`                 | Various | Extended attribute payloads          |
| `smb1_dialects.bin`             | < 1 KB  | Raw SMB1 negotiate dialect lists     |
| `compressible.dat`              | 1 MB    | Highly compressible data (text)      |
| `incompressible.dat`            | 1 MB    | Random bytes (incompressible)        |

### 6.2 Share Configuration

The target VM must have the following share configuration:

```ini
[testshare]
    path = /srv/smb/testshare
    read only = no
    browseable = yes
    guest ok = no
    durable handles = yes
    streams = yes
    acl xattr = yes
    oplocks = yes
    leases = yes
    compression = yes

[testshare-ro]
    path = /srv/smb/testshare-ro
    read only = yes
    browseable = yes

[testshare-guest]
    path = /srv/smb/testshare-guest
    guest ok = yes
```


## 7. CI Integration

### 7.1 Exit Code Protocol

| Code | Meaning                                         | CI Action        |
|------|--------------------------------------------------|------------------|
| 0    | All selected tests passed                        | Green build      |
| 1    | One or more tests failed (no crash)              | Red build        |
| 2    | Server crash or unrecoverable error detected     | Red build + alert |
| 3    | Infrastructure error (VM down, tool missing)     | Yellow build     |

### 7.2 CI Pipeline Integration

```yaml
# Example: GitHub Actions
ksmbd-torture:
  runs-on: self-hosted
  steps:
    - name: Start VM
      run: vm/vm-launch.sh VM3
    - name: Run quick smoke tests
      run: ./ksmbd-torture/ksmbd-torture.sh --quick --json results/smoke.json
    - name: Run full test suite
      if: github.event_name == 'push' && github.ref == 'refs/heads/master'
      run: ./ksmbd-torture/ksmbd-torture.sh --json results/full.json
    - name: Run benchmarks
      if: github.event_name == 'push' && github.ref == 'refs/heads/master'
      run: ./ksmbd-torture/ksmbd-torture.sh --benchmark --json results/bench.json
    - name: Upload results
      uses: actions/upload-artifact@v3
      with:
        name: torture-results
        path: results/
```

### 7.3 Result Retention

Each run produces a timestamped JSON file and log. The CI pipeline retains:
- Last 30 days of full test results
- Last 90 days of benchmark results (for trend analysis)
- Permanent retention of any run that detected a crash


## 8. Summary Statistics

| Metric                           | Count    |
|----------------------------------|----------|
| Test categories (functional)     | 49       |
| Benchmark categories             | 7        |
| Total categories                 | 56       |
| Total functional tests           | ~520     |
| Total benchmark tests            | ~40      |
| Total regression tests           | 43       |
| Total tests (all types)          | ~600     |
| Custom client tools              | 7        |
| Library modules                  | 7        |
| Implementation phases            | 4        |
| Estimated total effort           | 10 weeks |

This suite, combined with the KUnit tests in plans 01-07, provides defense in
depth: KUnit catches logic errors in isolation, ksmbd-torture catches integration
errors over the wire, and the benchmark suite catches performance regressions.
Together they cover the full spectrum from unit to system testing.
