# Program B Narrative Guide for New Contributors

## Who This Is For
This guide is for a new contributor who:
1. has little or no background in SMB
2. has never worked on Hyper-V compatibility
3. does not know NTFS internals
4. is not comfortable reading large C codebases yet

If that describes you, this document is the right place to start.

## What Program B Actually Is
Program B is the "maximum scope" project.

It is not just about fixing a few bugs in `ksmbd`.
It is the long-term plan for trying to make this Linux-based SMB server behave enough like Windows Server that Windows clients, Hyper-V, and Windows-oriented management workflows can rely on it.

That means Program B is about four big things at the same time:
1. `SMB protocol behavior`
2. `Windows-visible filesystem behavior`
3. `Hyper-V virtual-disk workflows`
4. `cluster/failover behavior`

Those four things interact with each other.
That is what makes the project hard.

## Start With the Small Truth
Before you understand Program B, you need to understand Program A.

Program A says:
- use Linux filesystems like `xfs` or `ext4`
- host `.vhdx` files as normal files
- make SMB behavior correct enough that Hyper-V can use them safely
- do not promise Windows parity

Program B goes further.
Program B asks:
- can we make this behave enough like Windows Server SMB that more Windows-specific features work?
- can we support Windows-like metadata expectations?
- can we support advanced Hyper-V scenarios like shared-disk workflows?
- can we eventually support some form of failover story?

So Program B is not a bugfix phase.
It is a platform-expansion phase.

## What We Are Building On
The main codebase is `ksmbd`.

At a high level:
1. Windows clients speak SMB to the Linux server.
2. `ksmbd` receives those SMB requests.
3. `ksmbd` maps them to Linux file operations, metadata operations, auth/session state, and network transports.

There is also `ksmbd-tools`, which handles some userspace tasks such as configuration and pieces of auth/user integration.

## What SMB Is, in Simple Terms
SMB is the protocol Windows uses for file sharing.

A client connects to a server and does things like:
1. authenticate
2. open a share
3. open a file
4. read or write data
5. lock it
6. ask for metadata
7. close it

That sounds simple, but Windows clients expect very specific behavior.

Examples:
1. If a network connection breaks, a file handle may be recoverable.
2. If multiple clients touch the same file, the lock and cache rules must match expectations.
3. If the client asks for a Windows metadata concept, the server must either provide it correctly or fail clearly.

SMB is not just "copy bytes over the network".
It is a long list of behavior promises.

## What Hyper-V Adds
Hyper-V is Microsoft’s virtualization platform.

Hyper-V can store virtual machine disks on SMB shares.
That means the SMB server is now holding files that are extremely important and extremely sensitive to correctness.

A normal document file can survive sloppy behavior better than a live VM disk can.
A virtual disk is different because:
1. writes must be ordered correctly
2. flush behavior matters
3. reconnect behavior matters
4. locks matter
5. corruption is catastrophic

When Hyper-V uses a `.vhdx` file over SMB, the SMB server is part of the storage path for the VM.
That is why Program A and Program B care so much about handles, reconnect, flush, and correctness.

## What NTFS Adds
NTFS is Windows’ main filesystem.

Windows clients often expect more than "a file exists".
They expect filesystem behavior that comes from NTFS concepts, for example:
1. short names (8.3 names)
2. object IDs
3. some compression behavior
4. Windows-flavored metadata
5. some admin operations and info classes

Linux filesystems like `xfs` and `ext4` do not natively act like NTFS.
That is the core reason Program B is hard.

The big mistake a newcomer can make is thinking:
"If Linux can read and write files, then Windows compatibility should be easy."

That is wrong.
A file server is not judged only by whether it stores bytes.
It is judged by whether it behaves like the client expects.

## What VHDX and RSVD Add
A `.vhdx` file is a Hyper-V virtual disk file.
If we only host it as a normal file, that is one level of complexity.

But shared-disk and advanced Hyper-V workflows can require more than normal file operations.
That is where `RSVD` comes in.

You do not need to know all the details yet.
The important point is this:
1. ordinary Hyper-V-over-SMB can work with the SMB server treating `.vhdx` as a file
2. advanced shared-disk workflows need storage behavior that is much closer to a virtual-disk platform

That is why this project separates:
1. `Program A`: normal Hyper-V over SMB
2. `Program B`: broader Windows + Hyper-V + possible RSVD/failover scope

## Why Program B Is Dangerous if Scoping Is Loose
Program B can grow out of control very quickly.

A newcomer should understand this immediately:
there is a massive difference between these two claims:
1. "Hyper-V can use VHDX files on our SMB share"
2. "We are compatible with Windows Server SMB + NTFS + Hyper-V"

The first claim is hard but reasonable.
The second claim is much larger and touches:
1. protocol details
2. filesystem semantics
3. metadata behavior
4. admin tool behavior
5. failover behavior
6. virtual-disk behavior
7. long-run support burden

That is why the hub documents are strict about claims.

## How the Codebase Is Roughly Organized
This is the practical map.
If you are new, keep this mental model.

### `src/core/`
General server behavior.

Think of this as the shared plumbing.
It includes things like:
1. server lifecycle
2. connection/work handling
3. general feature management

If you do not know where a high-level SMB request enters the system, this directory is part of the answer.

### `src/protocol/smb2/`
SMB2/SMB3 protocol handlers.

This is where many SMB requests are interpreted.
Examples:
1. negotiate
2. session setup
3. create/open
4. read/write
5. locks
6. query/set info
7. various control paths

If the client sends an SMB operation, there is a good chance important logic lives here.

For a new contributor, this is one of the most important directories.

### `src/fs/`
Filesystem-facing behavior.

This directory is important because it is where Windows-visible SMB behavior gets mapped onto Linux file and filesystem operations.

Examples:
1. open-file tracking
2. oplocks and leases
3. FSCTL behavior
4. info classes
5. metadata mapping
6. special features like RSVD and BranchCache

This directory is where a lot of the "Windows expectations versus Linux reality" tension shows up.

### `src/transport/`
Network transport implementations.

This is how SMB packets move.
Examples:
1. TCP transport
2. QUIC transport
3. RDMA transport

A transport bug can break everything above it.
If transport security or state transitions are wrong, all higher-level correctness becomes irrelevant.

### `src/mgmt/`
Management and server-side coordination pieces.

This includes things like witness-related code and config-oriented support logic.

### `ksmbd-tools/`
Userspace helper and management side.

This matters for:
1. auth integration
2. configuration
3. operational glue
4. some compatibility surfaces not appropriate for the kernel side

## The Most Important Technical Ideas You Must Learn First

### 1. Sessions, Tree Connects, and File Handles
A Windows client does not just "open a file".
It usually goes through a chain of state:
1. transport connection
2. authenticated session
3. tree connect to a share
4. file open/create
5. read/write/metadata/lock operations on that open file

If one step is broken, the later steps can look broken even if they are fine.

### 2. Durable and Persistent Handles
These are some of the most important ideas in the codebase for Hyper-V-style workloads.

Very simplified:
1. `durable handle`: client can reconnect after a temporary disconnect
2. `persistent handle`: stronger recovery expectations across more severe interruptions

Why they matter:
- a VM disk cannot just disappear because the network blinked

Why they are hard:
- the server must save enough state to reconnect safely
- it must not restore the wrong state
- locks, lease state, IDs, and access rights must still make sense

You do not need to understand every structure on day one.
You do need to understand that this is storage correctness, not a convenience feature.

### 3. Leases and Oplocks
These are Windows caching coordination mechanisms.

Simplified:
- the server tells a client how much caching freedom it has
- if another client needs conflicting access, the server may need to break or downgrade that caching promise

Why it matters:
- performance and correctness both depend on this
- VM workloads are very sensitive to incorrect cache-state behavior

### 4. Flush and Ordering
A write reaching the server is not the same as a write being safely persisted the way the guest expects.

For VM disks, this matters a lot.

A newcomer should remember this rule:
If you touch write, flush, cache, or reconnect behavior, assume you are touching data-integrity risk.

### 5. Metadata Translation
Windows clients ask for Windows-style metadata.
Linux filesystems expose Linux-style metadata.
`ksmbd` often has to translate between them.

This is where many Program B problems live.

Examples:
1. a client asks for a feature that exists on NTFS but not on `ext4`
2. the server must decide whether to:
   - implement it
   - emulate it
   - return not supported

That decision is architectural, not just local code cleanup.

## What Program B Needs That Program A Does Not
Program A mostly asks:
- can we safely host VM disk files over SMB?

Program B adds questions like:
1. can we reproduce more Windows-visible metadata behavior?
2. can we support advanced Hyper-V shared-disk workflows?
3. can we support multichannel/witness/failover stories closer to Windows Server?
4. can we justify stronger compatibility claims?

This is why Program B is separated in the planning hub.

## Important Documents in This Hub and Why They Exist

### `MEGAPLAN_WINDOWS_PARITY.md`
This is the top-level roadmap.
Read it if you want the broad strategy.

### `IMPLEMENTATION_BOARD.md`
This is the cross-program workstream board.
Read it if you want the overall structure of the work.

### `A_PROGRAM_MILESTONE_BOARD.md`
Read this if you want to understand what the project should ship first.

### `B_PROGRAM_FEASIBILITY_DECISION.md`
Read this if you want to understand why Program B is not automatically approved.

### `NTFS_BACKEND_ARCHITECTURE_OPTIONS.md`
Read this if you want to understand why NTFS parity is not a simple matter of writing a few handlers.

### `RSVD_VHDX_BACKEND_REQUIREMENTS.md`
Read this if you want to understand why shared-disk Hyper-V support is much more than ordinary file serving.

### `CLUSTER_FAILOVER_STATE_MODEL.md`
Read this if you want to understand why failover is a state architecture problem.

### `DECISION_PROPOSALS.md`
Read this for the recommended near-term project decisions.

### `DOCS_TO_CODE_MAPPING.md`
Read this when you want to connect planning docs to actual source files.

## A Beginner-Friendly Reading Order
If you are brand new, read in this order:
1. this file
2. `README.md`
3. `MEGAPLAN_WINDOWS_PARITY.md`
4. `DECISION_PROPOSALS.md`
5. `A_PROGRAM_MILESTONE_BOARD.md`
6. `DOCS_TO_CODE_MAPPING.md`
7. only then start opening source files

## Where a Junior Developer Should Start in the Code
Do not start with the hardest or most strategic files.
Start where you can build a map.

Recommended first reading:
1. `src/protocol/smb2/smb2_session.c`
2. `src/protocol/smb2/smb2_create.c`
3. `src/protocol/smb2/smb2_read_write.c`
4. `src/fs/vfs_cache.c`
5. `src/fs/oplock.c`
6. `src/core/server.c`

Why this order:
1. session and create paths show how requests become state
2. read/write shows how data flows
3. vfs_cache shows how file state is tracked
4. oplock shows how caching and reconnect get complicated
5. server.c helps show the larger lifecycle

## If You Are Weak in C, How to Read This Codebase Safely
You do not need to understand every line.

Use this method.

### Step 1: Read the function name and its inputs
Ask:
1. what is the function supposed to do?
2. what state does it receive?
3. what state can it change?

### Step 2: Ignore macros and details on the first pass
Do not get stuck on every helper or constant.
First, identify the main path:
1. validation
2. lookup
3. state update
4. error path
5. return

### Step 3: Track invariants, not syntax
Ask:
1. what must be true before this function runs?
2. what must be true after it succeeds?
3. what must be cleaned up if it fails?

### Step 4: Watch ownership and cleanup
In kernel C, many bugs come from:
1. wrong lifetime
2. forgotten cleanup
3. using freed or stale state
4. restoring inconsistent state

This matters a lot in handle, reconnect, and failover code.

## Norms for Working in This Project

### 1. Never Broaden Claims Casually
A feature is not "supported" because one happy-path test worked.
Claims must follow the validated matrix.

### 2. Prefer Honest `NOT_SUPPORTED` Over Fake Compatibility
Returning success for an unimplemented path is worse than returning a clean error.
A fake success creates data loss, management confusion, or client corruption.

### 3. Data Integrity Beats Feature Count
If you have to choose between:
1. a flashy compatibility feature
2. correct reconnect/flush/ordering semantics

choose correctness.
Always.

### 4. Architecture Before Parity
If a feature depends on NTFS-specific behavior, RSVD semantics, or failover state models, do not hack it in locally before the architecture is settled.

### 5. Tests Are Part of the Feature
In this project, implementation without Windows interoperability validation is incomplete.

## Common Traps for New Contributors

### Trap 1: Thinking Linux File Semantics Are Close Enough
They often are not.
Especially once Windows metadata expectations show up.

### Trap 2: Fixing the Happy Path Only
Reconnect, failover, lease breaks, and partial failure paths matter more than the easy path.

### Trap 3: Confusing Program A With Program B
Program A is about real, bounded Hyper-V-over-SMB support.
Program B is about much broader parity.
Do not write Program B code when solving a Program A problem unless the architecture already requires it.

### Trap 4: Treating RSVD Like a Small Filesystem Feature
It is not.
It is specialized storage behavior.

### Trap 5: Treating Failover Like a Transport Problem
It is not only a transport problem.
It is a distributed state problem.

## What Success Looks Like for a Junior Contributor
You do not need to solve NTFS parity or cluster failover.
A good first contribution might be:
1. improving a test matrix or test harness
2. documenting a state flow clearly
3. tightening an error path in durable handle logic
4. improving observability
5. validating a specific VM-disk behavior on one supported filesystem
6. turning an implicit assumption into an explicit invariant comment or check

That is real progress.

## What to Ask Before Starting a Change
1. Is this Program A or Program B work?
2. Is the support claim for this path already approved?
3. What state can this change corrupt if it is wrong?
4. Which Windows client behavior is this supposed to satisfy?
5. Which files in `DOCS_TO_CODE_MAPPING.md` are most relevant?
6. What is the failure mode if this change is incomplete?

## Suggested First Week Plan for a New Contributor
### Day 1
1. read this file
2. read `README.md`
3. read `DECISION_PROPOSALS.md`

### Day 2
1. read `MEGAPLAN_WINDOWS_PARITY.md`
2. read `A_PROGRAM_MILESTONE_BOARD.md`
3. skim `IMPLEMENTATION_BOARD.md`

### Day 3
1. read `DOCS_TO_CODE_MAPPING.md`
2. open the first five mapped Program A files
3. write your own short summary of what each file seems to do

### Day 4
1. trace one real request path
2. example: session setup -> create -> read/write -> close

### Day 5
1. pick one bounded task
2. write down:
   - what invariant it depends on
   - what files it touches
   - what test would prove it works

## Final Mental Model
The best simple summary is this:

Program B is an attempt to move from:
- "Linux SMB server that can host files for Windows clients"

toward:
- "Windows-compatible SMB storage platform"

That is why this project needs:
1. careful scoping
2. strong architecture
3. explicit claims
4. real validation

If you remember only one thing, remember this:
`the hardest part is not making the code compile; the hardest part is making the behavior trustworthy.`
