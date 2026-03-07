# Program A Narrative Guide for New Contributors

## Who This Is For
This guide is for a new contributor who:
1. is new to SMB
2. has never worked on Hyper-V storage
3. does not know the `ksmbd` codebase
4. is not confident reading large amounts of C

This guide explains Program A in plain language.

## What Program A Is
Program A is the first realistic product target.

It is not "Windows parity".
It is not "full NTFS compatibility".
It is not "cluster-grade Hyper-V support".

Program A is much narrower and much more practical.

The goal is:
- make `ksmbd` good enough that Hyper-V can reliably use SMB-hosted `VHDX` files on ordinary Linux filesystems like `xfs` or `ext4`

That means Program A is about:
1. correct SMB behavior
2. safe reconnect behavior
3. safe lock/lease behavior
4. correct write and flush behavior
5. stable authentication and operations
6. a real support matrix backed by validation

Program A is how this project becomes useful without making fake parity claims.

## Why Program A Exists
If you jump straight to full Windows parity, the project becomes too big and too vague.

Program A exists to answer a smaller, more important question first:

`Can we safely host Hyper-V virtual machine disk files over SMB on Linux-backed storage?`

That is already valuable.
It is also already hard.

So Program A is the disciplined first step.

## The One-Sentence Version
Program A is:
- `Hyper-V over SMB on Linux-backed filesystems, with narrow support claims and strong correctness requirements`

## What Program A Does Not Promise
A new contributor should memorize this early.

Program A does not promise:
1. full NTFS semantics
2. full Windows Server SMB parity
3. RSVD / shared-disk Hyper-V support
4. cluster-grade failover
5. SMB Direct in the initial release claim
6. QUIC in the initial release claim

This matters because you need to know when a feature request is actually Program B scope.

## Why Hyper-V Over SMB Is Still Hard
At first glance, this sounds easy.

A VM disk is just a file, right?

Not really.

A virtual disk file is extremely sensitive to:
1. write ordering
2. flush behavior
3. reconnect behavior
4. cache consistency
5. lock behavior
6. crash recovery behavior

A normal shared folder can tolerate more sloppiness.
A live VM disk cannot.

That is why Program A spends so much effort on "boring" things like:
1. durable handles
2. persistent handles
3. leases and oplocks
4. reconnect
5. flush semantics

Those are not side features.
They are the safety system for VM storage over SMB.

## The Basic System Model
Here is the simplified model.

1. A Windows host talks SMB to the Linux server.
2. The Linux server is `ksmbd`.
3. The Windows host opens a file on a share.
4. That file may be a `VHDX` virtual disk.
5. The host reads and writes through SMB.
6. `ksmbd` maps that behavior to Linux filesystem operations.

The key challenge is:
- Windows expects Windows-style SMB behavior
- Linux filesystems provide Linux-style file behavior
- `ksmbd` is the translation layer between them

Program A succeeds if that translation is safe enough for the supported Hyper-V use cases.

## Why Program A Uses Linux Filesystems and Not NTFS
Program A is intentionally built around Linux-native filesystems like `xfs` and `ext4`.

Why:
1. they are stable, common, and well-understood on Linux
2. they are better production targets for an early support claim
3. they avoid dragging the project into NTFS parity too early

This is an important mindset point.
Program A is not trying to make Linux act exactly like NTFS.
Program A is trying to make SMB behavior correct enough that Hyper-V can safely use files on Linux-backed storage.

That is a smaller and more achievable goal.

## What the Client Cares About in Program A
From the Hyper-V host’s point of view, these are the most important questions.

### 1. Can I open the file correctly?
That means:
1. auth works
2. share access works
3. file open semantics work

### 2. Can I keep using it if the network blinks?
That means:
1. durable or persistent handles work correctly
2. reconnect behavior is correct
3. lease/lock state remains consistent

### 3. Are my writes safe?
That means:
1. write ordering is correct
2. flush semantics are correct
3. sparse and zeroing behavior is correct enough for VHDX workflows

### 4. Is the server predictable?
That means:
1. errors are sensible
2. timeouts are sane
3. restarts and recovery are understood
4. support claims are honest

## The Most Important Technical Ideas in Program A

### Durable Handles
Think of these as a way to survive temporary disconnects.

If the client disconnects briefly, the server may keep enough state to let the client reconnect and continue using the file.

For VM storage, this is extremely important.

### Persistent Handles
These are stronger than ordinary durable handles.
They are about surviving tougher interruptions.

You do not need to know every detail yet.
Just remember:
1. they preserve important file state across disruption
2. if they are wrong, reconnect can become unsafe

### Leases and Oplocks
These tell clients what they are allowed to cache.

That matters for performance.
It also matters for correctness, because if the caching rules are wrong, one client may keep stale assumptions while another client changes the file.

For VM disks, that can be dangerous.

### Flush and Write Ordering
A write being accepted is not the same as a write being safely handled the way the guest OS expects.

If you touch write or flush behavior, always assume you are in a high-risk part of the system.

### Sparse Files and Zeroing
Virtual disk files often rely on sparse allocation and zeroing behavior.

That means Program A must care about:
1. allocation holes
2. zero-range behavior
3. how the underlying Linux filesystem behaves

## The Program A Source Map
If you are new, these directories matter most.

### `src/protocol/smb2/`
This is where many SMB requests are handled.

Important files for Program A include:
1. `smb2_session.c`
2. `smb2_create.c`
3. `smb2_read_write.c`
4. `smb2_lock.c`
5. `smb2_ioctl.c`
6. `smb2_query_set.c`

These files help answer:
- how does a Windows SMB request turn into server state and filesystem behavior?

### `src/fs/`
This is where Windows-visible behavior gets mapped to Linux file behavior.

Important files for Program A include:
1. `vfs.c`
2. `vfs_cache.c`
3. `oplock.c`
4. `ksmbd_fsctl.c`
5. `ksmbd_fsctl_extra.c`
6. `ksmbd_info.c`

These files help answer:
- how are open files tracked?
- how are leases/oplocks managed?
- how do FSCTL and metadata calls behave?

### `src/core/`
Important for:
1. server lifecycle
2. connection management
3. feature and work handling

Important files include:
1. `server.c`
2. `connection.c`

### `src/transport/`
Transport code matters because insecure or incorrect transport state breaks everything above it.

Important file for Program A risk analysis:
1. `transport_quic.c`

Even though Program A’s first release should be TCP-only, this transport work still matters for future support and for keeping the codebase honest.

### `ksmbd-tools/`
Important for userspace support pieces like:
1. auth integration
2. config behavior
3. operational support

## How Program A Is Structured in the Planning Hub
You do not need to guess what matters.

### `MEGAPLAN_WINDOWS_PARITY.md`
Top-level strategy.
Read this for the big picture.

### `A_PROGRAM_MILESTONE_BOARD.md`
This is the most important Program A execution document.
It tells you what the milestones actually are.

### `A_PROGRAM_TASK_TRACKER.md`
This is where the work gets broken into concrete tasks.

### `DECISION_PROPOSALS.md`
This tells you the recommended immediate decisions, including:
1. TCP-only first release
2. `xfs` and `ext4` only
3. no SMB Direct in the first support claim

### `DOCS_TO_CODE_MAPPING.md`
This connects the planning docs to actual source files.

### `WINDOWS_INTEROP_LAB_PLAN.md`
This explains how support claims are validated.

## Program A Milestones in Plain English

### A0 Scope Freeze
Decide what we are actually promising.
This stops scope creep.

### A1 Transport and Crypto Hardening
Make sure the transport layer is correct for the supported modes.

### A2 Durable and Persistent Handle Reliability
Make reconnect safe and correct.
This is one of the highest-priority technical areas.

### A3 VM-Disk I/O Semantics
Make sure reads, writes, flushes, sparse behavior, and checkpoint-related workflows are safe for Hyper-V.

### A4 Authentication and Session Stability
Make sure real deployments with auth and sessions do not fall apart under normal use.

### A5 Observability and Operations
Make the product operable in production.

### A6 Hyper-V Qualification Lab
Prove that the support claim is real.

## What a Junior Developer Should Focus On First
Do not start with broad architecture debates.
Start with understanding one concrete path.

Good first paths:
1. session setup -> create -> read/write -> close
2. create -> durable handle state -> reconnect
3. read/write -> flush -> close

This gives you a mental model of how SMB state turns into file behavior.

## Recommended First Files to Read
1. `src/protocol/smb2/smb2_session.c`
2. `src/protocol/smb2/smb2_create.c`
3. `src/protocol/smb2/smb2_read_write.c`
4. `src/fs/vfs_cache.c`
5. `src/fs/oplock.c`
6. `src/fs/vfs.c`
7. `src/core/server.c`

## How to Read This Code if You Are Weak in C

### Step 1: Identify the purpose of the function
Do not start with every macro.
Ask:
1. what is this function trying to do?
2. what request or state is it handling?

### Step 2: Find the state transitions
In this codebase, state transitions matter more than syntax.
Look for:
1. lookups
2. validation
3. field updates
4. cleanup
5. failure returns

### Step 3: Track invariants
Ask:
1. what must be true before this function starts?
2. what must be true if it succeeds?
3. what cleanup must happen if it fails?

### Step 4: Respect lifetimes
Many dangerous bugs in kernel C are lifetime bugs.
Examples:
1. stale handle IDs
2. wrong cleanup order
3. reusing state after reconnect incorrectly
4. losing a lock or lease invariant

## Program A Norms

### 1. Correctness Over Feature Count
If a change increases risk in reconnect, caching, flush, or ordering behavior, it is high risk even if it looks small.

### 2. Narrow Honest Claims
Program A wins by making a smaller claim correctly, not by sounding like Windows Server.

### 3. Explicit Support Matrix
A feature is not supported because it seems to work once.
It is supported because it passes the matrix in the lab.

### 4. Do Not Smuggle Program B into Program A
If your change depends on:
1. NTFS parity
2. RSVD
3. cluster-grade failover
4. broad Windows metadata emulation

that is probably Program B territory.

### 5. Failure Paths Matter
If reconnect or restart breaks the system, the happy path does not matter.

## Common Program A Mistakes

### Mistake 1: Treating VHDX as "just another file"
It is a file, but it carries VM-disk correctness demands.

### Mistake 2: Thinking reconnect is optional polish
For Hyper-V-style workloads, reconnect behavior is core functionality.

### Mistake 3: Ignoring the backing filesystem
Program A explicitly limits the matrix for a reason.
Behavior can differ by filesystem.

### Mistake 4: Adding a support claim before lab proof
This project must be stricter than that.

### Mistake 5: Getting stuck in code before reading the hub docs
The planning docs tell you where the boundaries are.
Without them, it is easy to work on the wrong thing.

## What Good Program A Contributions Look Like
A good junior contribution might be:
1. clarifying a durable-handle failure path
2. improving logging around reconnect
3. documenting an invariant in handle or lease code
4. adding test coverage for a flush or reconnect scenario
5. validating one Hyper-V workflow on one supported filesystem
6. turning a vague unsupported path into a deliberate error return with documentation

Those are all valuable.

## Questions to Ask Before Starting a Change
1. Is this inside the Program A support claim?
2. Which milestone does this belong to?
3. Which exact files are involved according to `DOCS_TO_CODE_MAPPING.md`?
4. What is the data-integrity risk if this is wrong?
5. What test would prove the fix?
6. Is there a reconnect, lease, lock, or flush consequence?

## Suggested First Week Plan
### Day 1
1. read this file
2. read `README.md`
3. read `DECISION_PROPOSALS.md`

### Day 2
1. read `A_PROGRAM_MILESTONE_BOARD.md`
2. read `A_PROGRAM_TASK_TRACKER.md`
3. skim `IMPLEMENTATION_BOARD.md`

### Day 3
1. read `DOCS_TO_CODE_MAPPING.md`
2. open the first mapped Program A files
3. write down what each file seems to own

### Day 4
1. trace one request path end to end
2. example: open a file and follow the handle state

### Day 5
1. pick one small task
2. write down:
   - files touched
   - invariant changed
   - expected test

## Final Mental Model
Program A is the disciplined part of the project.

It says:
- we are not trying to do everything
- we are trying to do one valuable thing correctly

That one thing is:
- safe, supportable Hyper-V over SMB on Linux-backed storage

If you remember only one sentence, remember this:
`Program A is about making the smaller promise true before anyone is allowed to make a bigger promise.`
