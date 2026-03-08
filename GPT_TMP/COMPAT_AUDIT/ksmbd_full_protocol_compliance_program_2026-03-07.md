# ksmbd Full Protocol Compliance Assessment and Execution Plan

Date: 2026-03-07

## Goal

Build a realistic program plan to bring ksmbd to full protocol compliance across:

- SMB1
- SMB2 / SMB2.1 / SMB3.0 / SMB3.0.2 / SMB3.1.1
- SMB Direct / RDMA
- SMB over QUIC
- Apple SMB extensions
- Named pipes and RPC
- Full FSCTL surface

This document is a program plan, not a patch plan. The scope is large enough that "100% compliant" must be treated as a product program with a spec matrix, implementation milestones, interop gates, and release criteria.

## What "100% Compliant" Must Mean

For this program, ksmbd is only allowed to claim full compliance when all of the following are true:

1. Every protocol feature in scope is either:
   - implemented to the relevant Microsoft or Apple behavior contract, or
   - not advertised, not negotiated, and not reachable by clients.
2. Capability bits, negotiate contexts, create contexts, FSCTL support, transport support, and RPC endpoints are truthful.
3. The implementation passes:
   - unit tests
   - fuzzing
   - interoperability tests
   - protocol conformance tests
   - long-duration stress tests
4. The supported behavior is documented command-by-command and dialect-by-dialect.
5. There are no known red failures in the interoperability matrix for in-scope features.

This definition matters because protocol compliance is not just "does code exist"; it is "does the server advertise the right thing, accept the right thing, reject the wrong thing, and emit the right wire behavior."

## Current Assessment

Current state: partially compliant, not claim-ready for full protocol coverage.

Main conclusions from the current tree and existing sweep artifacts:

- SMB2/SMB3 core server paths exist and many validations are present, but several advertised capabilities are still behaviorally wrong.
- Multichannel and session binding are not correct for the full SMB3 family.
- Durable handle, lease, directory lease, replay, and notify paths still show interoperability failures.
- RDMA support exists, but negotiate/runtime transform behavior is still inconsistent and not yet claim-safe.
- QUIC exists as a large implementation surface, but it needs its own conformance program and transport-security verification.
- SMB1 is no longer a trivial parser-only surface; it is a partially implemented production protocol with known intentional gaps.
- Named pipes, RPC, and FSCTL support exist, but the surface is incomplete and uneven.
- Apple extensions are beyond "basic" now, but still need explicit parity and interoperability verification against macOS client expectations.

Bottom line:

- ksmbd can become highly compliant.
- ksmbd cannot honestly become fully compliant by incremental bug-fixing alone.
- It needs a full compliance program.

## Program Principles

The program should follow five rules.

### Rule 1: Truth before breadth

If a feature is not complete, stop advertising it before expanding scope.

Examples:

- Do not advertise a negotiate context unless the runtime behavior matches it.
- Do not expose SMB1 by default if SMB1 transactions are intentionally partial.
- Do not advertise RDMA transforms that are not enforced.

### Rule 2: Spec matrix drives engineering

Every command, context, FSCTL, transport feature, and RPC endpoint needs an explicit compliance row:

- Spec section
- Supported dialects
- Advertised?
- Implemented?
- Tested?
- Known deviations
- Blocking defects

### Rule 3: Interop is a release gate

No feature is complete until it passes against real clients and reference servers.

### Rule 4: Transport-specific behavior must be isolated

TCP, RDMA, and QUIC must not share ambiguous flags or overloaded state that can corrupt negotiate semantics.

### Rule 5: Optional features must be explicit

If a feature is optional in the spec, ksmbd may choose not to support it, but then it must not be negotiated or exposed. Because this program targets full scope, the plan below assumes implementation rather than omission.

## Program Structure

This is a multi-workstream, multi-phase effort. The cleanest structure is:

- Phase 0: Compliance contract and infrastructure
- Phase 1: SMB2/SMB3 core correctness
- Phase 2: Durable / lease / notify / replay closure
- Phase 3: FSCTL completion
- Phase 4: Named pipes and RPC completion
- Phase 5: SMB1 closure
- Phase 6: RDMA closure
- Phase 7: QUIC closure
- Phase 8: Apple extension closure
- Phase 9: Hardening, interop certification, and release

## Phase 0: Compliance Contract and Infrastructure

### Objectives

- Define the full in-scope protocol surface.
- Build the compliance matrix.
- Build the testing and CI structure that will prevent regressions.

### Deliverables

- `COMPLIANCE_MATRIX.md`
- `COMPLIANCE_MATRIX.csv`
- Feature/dialect support table
- Interop client matrix
- Test ownership map
- Release gate definition

### Work

- Enumerate all commands by protocol family:
  - SMB1 command set
  - SMB1 transaction / trans2 / nt transact subcommands
  - SMB2/3 commands
  - create contexts
  - negotiate contexts
  - info classes
  - ioctl/fsctl codes
  - named-pipe operations
  - RPC interfaces and opnums
- Map each item to its normative spec section.
- Split each item into:
  - parser correctness
  - access control semantics
  - state machine semantics
  - response/status code correctness
  - async behavior
  - transport-specific behavior
- Build a machine-readable pass/fail matrix.

### Exit Criteria

- No feature exists without a compliance row.
- CI can report compliance status by feature area.

## Phase 1: SMB2/SMB3 Core Correctness

### Objectives

- Make negotiate, session, tree, create, read/write, lock, query/set, ioctl, and misc command behavior spec-clean for SMB2+.

### Priority defects to close first

- Multichannel binding for SMB 3.0 / 3.0.2 / 3.1.1
- Negotiate-context semantics:
  - compression
  - signing capabilities
  - encryption capabilities
  - RDMA transform capabilities
  - transport capabilities
- Capability-bit correctness:
  - encryption
  - multichannel
  - persistent handles
  - notifications
  - DFS

### Work

- Audit every SMB2/3 command handler for:
  - request size checks
  - compound handling
  - async status behavior
  - status code correctness
  - session/tree/file identity validation
  - replay handling
  - dialect-specific branches
- Create a per-command compliance sheet for:
  - NEGOTIATE
  - SESSION_SETUP
  - LOGOFF
  - TREE_CONNECT / DISCONNECT
  - CREATE / CLOSE / FLUSH
  - READ / WRITE
  - LOCK
  - IOCTL
  - QUERY_INFO / SET_INFO
  - QUERY_DIRECTORY
  - CHANGE_NOTIFY
  - ECHO
  - OPLOCK_BREAK

### Exit Criteria

- All SMB2/3 commands are mapped to spec sections and covered by tests.
- No known false advertisement remains in negotiate or capabilities.
- `smbtorture` core suites are green or deviations are explicitly documented as out-of-scope.

## Phase 2: Durable Handles, Leases, Oplocks, Replay, Notify

### Objectives

- Stabilize the hardest SMB2/3 stateful compatibility surface.

### Why this is a separate phase

This is the area most likely to fail even when parsers and status mappings are correct. The current artifacts already show failures here.

### Work

- Durable handle v1:
  - open
  - disconnect
  - reconnect
  - timeout
- Durable handle v2:
  - request
  - reconnect
  - replay
  - persistent flag semantics
  - create-guid handling
- Persistent handles:
  - capability truthfulness
  - restore path
  - cluster/HA assumptions
- Leases:
  - read/write/handle caching transitions
  - lease epochs
  - parent lease key handling
  - directory lease exemptions
- Oplocks:
  - break ordering
  - required ACK behavior
  - sync vs async downgrade paths
- Replay:
  - create replay
  - durable replay
  - session replay
- Notify:
  - delivery
  - cancellation
  - timeout
  - change coalescing
  - correct async completion

### Required test expansion

- `smbtorture`:
  - `durable-open`
  - `durable-v2-open`
  - `replay`
  - `lease`
  - `dirlease`
  - `notify`
  - `compound_async`
  - `kernel-oplocks`
- Packet trace comparisons against Samba and Windows Server
- Long soak runs with reconnect/replay fault injection

### Exit Criteria

- No red failures in durable/lease/replay/notify suites.
- Fault-injection reconnect testing is stable.

## Phase 3: FSCTL Completion

### Objectives

- Implement the full intended FSCTL surface with correct status codes, response structures, and transport constraints.

### Work Breakdown

Split FSCTLs into families:

- File/data management
  - sparse
  - zero data
  - allocated ranges
  - file level trim
  - duplicate extents
  - copychunk
  - ODX/offload-related flows
- Information and metadata
  - object ID
  - retrieval pointers
  - volume data
  - volume bitmap
  - network interface info
  - validate negotiate info
- Reparse and namespace
  - reparse points
  - DFS-related controls
  - snapshots / previous versions
- Quota and security
  - quota controls
  - security-related FSCTLs
- Named pipes
  - pipe wait
  - pipe peek
  - pipe transceive
- Cluster / remote / reserved controls
  - reserved / pass-through / unsupported controls with correct responses

### Required method

- Build a complete FSCTL inventory from `MS-FSCC`.
- For each code, classify:
  - mandatory
  - optional but in-scope for this program
  - unsupported by design
- For unsupported-by-design controls:
  - return the exact required status
  - do not falsely imply support

### Exit Criteria

- Every in-scope FSCTL has a compliance row and a test.
- No FSCTL handler is a compatibility stub unless explicitly marked unsupported by the spec matrix.

## Phase 4: Named Pipes and RPC Completion

### Objectives

- Make IPC$, named-pipe behavior, and RPC transport semantics interoperable with Windows and Samba expectations.

### Work

- Named pipe object semantics:
  - create/open rules
  - blocking behavior
  - read/write behavior
  - transceive behavior
  - peek state
  - wait semantics
  - disconnect/close semantics
- RPC interface completeness:
  - `srvsvc`
  - `wkssvc`
  - `samr`
  - `lsarpc`
  - RAP compatibility where required
- RPC transport behavior:
  - open/close lifecycle
  - fragmenting/reassembly
  - NDR correctness
  - zero-length and partial read/write cases
  - async and credit interactions

### Important policy decision

Full RPC compliance does not only mean "pipe open works". It means the exposed interfaces, opnums, handles, and error semantics are coherent. If ksmbd exposes an interface, it needs a completeness target per opnum.

### Exit Criteria

- Named-pipe tests pass for read/write/transceive/peek/wait paths.
- Exposed RPC interfaces have documented supported opnum sets and pass interop tests.

## Phase 5: SMB1 Closure

### Objectives

- Either complete SMB1 as a real supported protocol, or remove it from the default production surface.

This program assumes completion because the requested target includes full SMB1 compliance.

### Work Breakdown

- NEGOTIATE / SESSION_SETUP / TREE_CONNECT / LOGOFF
- Open/create/close/flush/read/write
- TRANS / TRANS2 / NT_TRANSACT families
- FIND / TRANS2_FIND_* behavior
- LOCKING_ANDX and share-mode behavior
- SMB1 notifications
- SMB1 FSCTL / ioctl bridging
- SMB1 signing behavior
- Legacy info classes and DOS attribute semantics
- Named-pipe behavior on SMB1 IPC$

### Hard reality

SMB1 is effectively a separate server product inside ksmbd. It has its own:

- parser rules
- transport behavior
- transaction formats
- status mappings
- compatibility expectations

### Required policy

- Until the SMB1 matrix is green, do not enable it by default in external builds.

### Exit Criteria

- Every implemented SMB1 command and subcommand has a compliance row and tests.
- SMB1 `smbtorture` / legacy client validation passes for the supported surface.

## Phase 6: RDMA / SMB Direct Closure

### Objectives

- Make SMB Direct compliance real, not partial.

### Work

- SMB Direct negotiate and connection setup
- Credit accounting and exhaustion behavior
- Buffer descriptor validation
- RDMA read/write paths
- RDMA transform handling:
  - encryption
  - signing
  - transform header formation
  - decrypt/verify on inbound paths
- Multichannel interaction
- Session binding on RDMA channels
- Error handling on disconnect/reconnect

### Required verification

- Compare wire behavior to `MS-SMB2` RDMA sections
- Run dedicated RDMA interop against Windows clients and Samba where possible
- Stress credit and completion paths under load

### Exit Criteria

- No transform or credit mismatch between negotiate and runtime behavior.
- RDMA tests pass with and without transforms enabled.

## Phase 7: QUIC Closure

### Objectives

- Bring SMB over QUIC to conformance-grade behavior.

### Work

- QUIC transport conformance:
  - version handling
  - packet parsing
  - Retry behavior
  - connection IDs
  - stream handling
  - close/error semantics
- TLS 1.3 handshake delegation correctness
- Transport-security signaling into SMB negotiate
- Session/channel binding over QUIC
- Encryption/signing policy interactions with SMB3
- Loss, reorder, retransmit, and fragmentation handling

### Special caution

QUIC compliance is not just SMB compliance. It is:

- RFC 9000
- RFC 9001
- SMB over QUIC behavior
- transport-security interaction with SMB3 negotiate/session rules

### Exit Criteria

- QUIC passes protocol conformance testing and SMB interop testing.
- Transport-security negotiate semantics are correct and isolated from TCP/RDMA.

## Phase 8: Apple Extension Closure

### Objectives

- Reach explicit compatibility parity for in-scope Apple behaviors.

### Work

- AAPL negotiate/create-context behavior
- Finder metadata behavior
- Time Machine requirements
- resource fork / stream behavior
- durable/lease interactions with macOS clients
- Apple-specific FSCTL or ioctl expectations if exposed
- correctness against current macOS Finder and Time Machine workflows

### Required validation

- macOS functional testing:
  - browse
  - copy
  - rename
  - metadata preservation
  - Time Machine sparsebundle operations
- compare behavior against Samba `fruit` where applicable

### Exit Criteria

- No Apple extension behavior is advertised without verified behavior.
- macOS client workflows pass end-to-end.

## Phase 9: Hardening, Certification, and Release

### Objectives

- Convert feature-complete into release-complete.

### Work

- Red-team protocol fuzzing
- long-duration soak tests
- multi-client concurrency
- packet-capture regression checks
- docs and support statements
- feature flags and deployment guidance

### Release criteria

- Compliance matrix has no unowned red items
- CI is green
- Interop matrix is green
- all advertised features have passing tests
- default configuration is truthful and safe

## Test Strategy

The program cannot succeed without a hard test program.

### Test Layers

- KUnit
  - parser logic
  - state machine helpers
  - boundary conditions
  - status mapping
- fuzzing
  - command parsers
  - create contexts
  - negotiate contexts
  - FSCTLs
  - NDR/RPC
  - QUIC
  - RDMA descriptors
- `smbtorture`
  - per-suite tracking
  - per-dialect tracking
  - per-transport tracking
- real-client interop
  - Windows
  - Samba client stack
  - Linux CIFS
  - macOS
- soak and stress
  - long file workloads
  - reconnect storms
  - notify storms
  - lease break races
  - multichannel failover

### CI Requirements

- Per-commit:
  - build
  - static checks
  - targeted KUnit
  - targeted fuzz smoke
- Nightly:
  - full KUnit
  - selected `smbtorture`
  - protocol regression suites
- Weekly:
  - extended interop matrix
  - soak runs
  - packet diffing against reference servers

## Required Artifacts

To run this program well, create and maintain:

- `COMPLIANCE_MATRIX.md`
- `COMMAND_MATRIX_SMB1.md`
- `COMMAND_MATRIX_SMB2_3.md`
- `FSCTL_MATRIX.md`
- `RPC_INTERFACE_MATRIX.md`
- `TRANSPORT_MATRIX.md`
- `APPLE_COMPAT_MATRIX.md`
- `INTEROP_RESULTS/`
- `PCAP_BASELINES/`
- `KNOWN_DEVIATIONS.md`

## Recommended Execution Order

Do not attack all workstreams at once. The lowest-risk order is:

1. Phase 0: build the compliance matrix
2. Phase 1: fix SMB2/SMB3 negotiate/session capability truthfulness
3. Phase 2: stabilize durable/lease/replay/notify
4. Phase 3: complete FSCTLs
5. Phase 4: complete named pipes and RPC
6. Phase 6: finish RDMA truthfulness and transforms
7. Phase 7: finish QUIC transport correctness
8. Phase 8: finalize Apple parity
9. Phase 5: close SMB1 fully
10. Phase 9: certify and freeze

Reason:

- SMB2/SMB3 truthfulness affects everything else.
- Durable/lease/replay are the highest-risk SMB2/3 interoperability blockers.
- FSCTL and named-pipe correctness are prerequisites for serious client compatibility.
- RDMA and QUIC must not be finalized on top of unstable core semantics.
- SMB1 should be finished only with a disciplined matrix in place, because it expands the surface dramatically.

## Staffing Model

This is not one engineer's patch queue. A realistic team split is:

- Core SMB2/SMB3 owner
- durable/lease/notify owner
- FSCTL / info class owner
- RPC / named-pipe owner
- SMB1 owner
- RDMA owner
- QUIC owner
- Apple extension owner
- QA / interop owner

One person can cover multiple areas temporarily, but the workstreams should be tracked separately.

## Risks

Main program risks:

- false-positive confidence from unit tests without real-client interop
- hidden transport coupling between TCP, RDMA, and QUIC
- SMB1 scope explosion
- partial RPC exposure that appears complete to clients
- capability advertisement outrunning behavior
- regressions in durable/lease semantics while fixing multichannel or transports

## Final Assessment

Full compliance is achievable as an engineering program, but not as a short bugfix cycle.

The most important first move is not "implement everything immediately". It is:

- define the full compliance matrix
- stop lying on the wire
- close core SMB2/SMB3 behavior first
- then finish the extended protocol surfaces in controlled workstreams

If this program is executed with strong gates, ksmbd can reach a defensible compliance claim. Without the matrix, CI, and interop discipline, the codebase will continue to drift into the current state: many features present, but too many of them only partially trustworthy.
