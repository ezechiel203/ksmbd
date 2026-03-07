# New Contributor Reading Path

## Purpose
This document gives a junior contributor a single, practical reading path for the first week.

It assumes:
1. little or no SMB background
2. no Hyper-V background
3. no NTFS background
4. limited confidence reading C

## Rule for the First Week
Do not start by trying to understand every line of code.

First understand:
1. what the project is trying to achieve
2. what Program A is
3. what Program B is
4. where the main state lives
5. which files matter most

Only after that should you start tracing logic in detail.

## Day 1: Understand the Project Shape
Read these in order:
1. [README.md](./README.md)
2. [PROGRAM_A_NARRATIVE_GUIDE.md](./PROGRAM_A_NARRATIVE_GUIDE.md)
3. [PROGRAM_B_NARRATIVE_GUIDE.md](./PROGRAM_B_NARRATIVE_GUIDE.md)
4. [GLOSSARY.md](./GLOSSARY.md)

Goal for Day 1:
1. understand the difference between Program A and Program B
2. understand that Program A is the real near-term product target
3. understand that Program B is much larger and more architectural

Questions you should be able to answer by the end of Day 1:
1. What is Program A trying to ship?
2. What is Program B trying to become?
3. Why is Hyper-V-over-SMB harder than normal file serving?
4. Why is NTFS parity not the same thing as basic SMB correctness?

## Day 2: Understand Scope and Claims
Read these in order:
1. [MEGAPLAN_WINDOWS_PARITY.md](./MEGAPLAN_WINDOWS_PARITY.md)
2. [DECISION_PROPOSALS.md](./DECISION_PROPOSALS.md)
3. [PROGRAM_B_RELEASE_CLAIMS.md](./PROGRAM_B_RELEASE_CLAIMS.md)

Goal for Day 2:
1. understand the current recommended scope decisions
2. understand what the project is allowed to claim and what it is not
3. understand why narrow support claims matter

Questions you should be able to answer by the end of Day 2:
1. Why is Program A TCP-only in the recommended first release?
2. Why is SMB Direct deferred?
3. Why are `xfs` and `ext4` the recommended first backing filesystems?
4. Why is Program B intentionally not yet approved?

## Day 3: Understand the Execution Plan
Read these in order:
1. [IMPLEMENTATION_BOARD.md](./IMPLEMENTATION_BOARD.md)
2. [A_PROGRAM_MILESTONE_BOARD.md](./A_PROGRAM_MILESTONE_BOARD.md)
3. [A_PROGRAM_TASK_TRACKER.md](./A_PROGRAM_TASK_TRACKER.md)
4. [WORKSTREAM_REGISTER.md](./WORKSTREAM_REGISTER.md)
5. [DELIVERY_SEQUENCE.md](./DELIVERY_SEQUENCE.md)

Goal for Day 3:
1. understand the order in which work should happen
2. understand the critical path for Program A
3. understand which workstreams are cross-cutting

Questions you should be able to answer by the end of Day 3:
1. What blocks Program A from shipping?
2. Which milestone is most dangerous for data integrity?
3. Which tasks are on the Program A critical path?
4. Which workstreams belong only to Program B?

## Day 4: Connect the Plan to the Code
Read these in order:
1. [DOCS_TO_CODE_MAPPING.md](./DOCS_TO_CODE_MAPPING.md)
2. [NTFS_BACKEND_ARCHITECTURE_OPTIONS.md](./NTFS_BACKEND_ARCHITECTURE_OPTIONS.md)
3. [RSVD_VHDX_BACKEND_REQUIREMENTS.md](./RSVD_VHDX_BACKEND_REQUIREMENTS.md)
4. [CLUSTER_FAILOVER_STATE_MODEL.md](./CLUSTER_FAILOVER_STATE_MODEL.md)

Goal for Day 4:
1. understand which source files matter for which feature areas
2. understand which problems are implementation problems and which are architecture problems
3. understand why some Program B work cannot be started casually

Questions you should be able to answer by the end of Day 4:
1. Which files are likely to matter first for Program A?
2. Why is RSVD not just a small SMB feature?
3. Why is failover a state-model problem?
4. Why does NTFS parity need an architecture decision?

## Day 5: First Source Walkthrough
Open these files and read them slowly:
1. [src/protocol/smb2/smb2_session.c](/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_session.c)
2. [src/protocol/smb2/smb2_create.c](/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_create.c)
3. [src/protocol/smb2/smb2_read_write.c](/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_read_write.c)
4. [src/fs/vfs_cache.c](/home/ezechiel203/ksmbd/src/fs/vfs_cache.c)
5. [src/fs/oplock.c](/home/ezechiel203/ksmbd/src/fs/oplock.c)
6. [src/core/server.c](/home/ezechiel203/ksmbd/src/core/server.c)

How to read them:
1. do not try to understand everything
2. find major functions
3. identify request entry points, lookups, state updates, and failure paths
4. write down in plain English what each file seems to own

Goal for Day 5:
1. build a mental map of the core request and file-state path

Questions you should be able to answer by the end of Day 5:
1. Where does session setup logic live?
2. Where does create/open logic live?
3. Where is file-open state tracked?
4. Where are leases/oplocks managed?
5. Where does high-level server request handling start?

## Day 6: Trace One Real Path
Pick one of these paths and trace it with notes:
1. session setup -> tree connect -> create -> read/write -> close
2. create -> durable handle -> disconnect -> reconnect
3. create -> lease/oplock grant -> conflicting access -> break/recovery

Suggested files to cross-reference:
1. [src/protocol/smb2/smb2_session.c](/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_session.c)
2. [src/protocol/smb2/smb2_create.c](/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_create.c)
3. [src/protocol/smb2/smb2_lock.c](/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_lock.c)
4. [src/fs/vfs_cache.c](/home/ezechiel203/ksmbd/src/fs/vfs_cache.c)
5. [src/fs/oplock.c](/home/ezechiel203/ksmbd/src/fs/oplock.c)

Goal for Day 6:
1. stop seeing the codebase as unrelated files
2. start seeing state flow across subsystems

Output you should write for yourself:
1. one page of notes describing the path in plain English
2. a list of 3-5 invariants you think the path depends on

## Day 7: Pick a Bounded Contribution
Before touching code, read these:
1. [GOVERNANCE.md](./GOVERNANCE.md)
2. [RISK_REGISTER.md](./RISK_REGISTER.md)
3. [DECISION_LOG.md](./DECISION_LOG.md)

Then choose one bounded task.
Good starter task types:
1. document a state invariant
2. improve error-path logging
3. add or clarify a support-boundary comment
4. validate a specific Program A behavior on a supported filesystem
5. trace and summarize one reconnect or flush path for the team

Goal for Day 7:
1. choose something narrow, useful, and safe

## If You Get Lost
Go back to these three files first:
1. [README.md](./README.md)
2. [PROGRAM_A_NARRATIVE_GUIDE.md](./PROGRAM_A_NARRATIVE_GUIDE.md)
3. [DOCS_TO_CODE_MAPPING.md](./DOCS_TO_CODE_MAPPING.md)

Those three documents should be enough to re-anchor you.

## Anti-Patterns for New Contributors
Do not do these in the first week:
1. do not start with Program B implementation ideas
2. do not start with RSVD
3. do not start with failover semantics
4. do not assume NTFS parity is "just metadata"
5. do not broaden the support claim in your own head beyond what the docs say

## Success Criteria for the First Week
At the end of the first week, a new contributor should be able to explain:
1. what Program A is
2. why Program B is bigger and riskier
3. which source files matter most for Program A
4. why durable handles, leases, flushes, and reconnect matter for Hyper-V
5. which kinds of changes are safe beginner work and which are not

## The Most Important Final Reminder
You are not trying to prove you can read all of `ksmbd`.

You are trying to build a reliable map of:
1. project goals
2. support boundaries
3. core state flows
4. dangerous subsystems

That map is more valuable than pretending to understand every line of C immediately.
