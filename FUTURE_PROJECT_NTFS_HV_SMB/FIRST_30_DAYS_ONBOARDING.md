# First 30 Days Onboarding

## Purpose
This document turns the onboarding material in this hub into a practical first-month plan for a junior contributor.

It assumes the contributor:
1. is new to SMB
2. is new to Hyper-V storage
3. is weak in C
4. needs a safe path into the codebase without being overwhelmed

## Core Rule
The first 30 days are not about becoming an expert in every subsystem.

They are about building:
1. a reliable mental map
2. good habits around scope and claims
3. the ability to trace one path end to end
4. the ability to make small, safe, useful contributions

## Success Criteria by Day 30
By the end of the first month, a junior contributor should be able to:
1. explain Program A and Program B clearly
2. identify the high-risk parts of the codebase
3. trace at least two real request/state paths through the code
4. explain why reconnect, leases, flush, and write ordering matter
5. understand the support matrix discipline of the project
6. complete one or two safe starter contributions
7. write clear notes about invariants and failure paths

## Month Structure
The month is split into four phases:
1. Week 1: orientation and reading
2. Week 2: code tracing and state mapping
3. Week 3: validation thinking and subsystem focus
4. Week 4: safe contribution and review habits

## Week 1: Orientation and Reading
Use [NEW_CONTRIBUTOR_READING_PATH.md](./NEW_CONTRIBUTOR_READING_PATH.md) as the daily guide.

### Week 1 Goals
1. understand Program A versus Program B
2. understand the support-claim boundaries
3. understand the top-level code layout
4. identify the first core source files

### Deliverables by End of Week 1
1. a one-page plain-English summary of Program A
2. a one-page plain-English summary of Program B
3. a short list of the source files that seem most important for Program A
4. a list of terms the contributor still does not understand

### Good Mentor Checkpoint Questions
1. What is the difference between Program A and Program B?
2. Why is Hyper-V-over-SMB not the same as Windows parity?
3. Why are durable handles important?
4. Why does the project prefer narrow support claims?

## Week 2: Code Tracing and State Mapping
Week 2 is about following state, not memorizing syntax.

### Reading Focus
Open and revisit these files:
1. [src/protocol/smb2/smb2_session.c](/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_session.c)
2. [src/protocol/smb2/smb2_create.c](/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_create.c)
3. [src/protocol/smb2/smb2_read_write.c](/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_read_write.c)
4. [src/fs/vfs_cache.c](/home/ezechiel203/ksmbd/src/fs/vfs_cache.c)
5. [src/fs/oplock.c](/home/ezechiel203/ksmbd/src/fs/oplock.c)
6. [src/core/server.c](/home/ezechiel203/ksmbd/src/core/server.c)

### Tracing Exercises
#### Exercise 1: Session to File Open
Trace this path at a high level:
1. client connects
2. session setup
3. tree connect
4. create/open
5. file state stored

Write down:
1. which file owns each step
2. which structures seem to represent session, share, and open-file state
3. what can fail at each step

#### Exercise 2: File Open to Read/Write
Trace:
1. create/open path
2. read/write path
3. close path

Write down:
1. where the open file is looked up
2. where access checks seem to happen
3. where the operation touches the Linux filesystem

#### Exercise 3: Durable/Persistent Handle Reconnect
Trace:
1. open/create with durable or persistent context
2. where state is saved
3. where reconnect looks state up
4. where restore and reopen happen

Write down:
1. what IDs matter
2. where cleanup seems dangerous
3. what invariants reconnect depends on

### Week 2 Goals
1. stop treating the codebase as isolated files
2. start seeing request and state flows
3. identify the places where data-integrity risk is highest

### Deliverables by End of Week 2
1. a plain-English trace of one session/open path
2. a plain-English trace of one durable/reconnect path
3. a list of 5-10 invariants the contributor thinks are important

### Good Mentor Checkpoint Questions
1. Where is open-file state tracked?
2. What is the difference between durable and persistent handles in practical terms?
3. Why are reconnect bugs dangerous for VM storage?
4. Where would you look first if reconnect started failing?

## Week 3: Validation Thinking and Subsystem Focus
Week 3 teaches the contributor to think in terms of support claims and tests, not only code edits.

### Documents to Revisit
1. [A_PROGRAM_MILESTONE_BOARD.md](./A_PROGRAM_MILESTONE_BOARD.md)
2. [A_PROGRAM_TASK_TRACKER.md](./A_PROGRAM_TASK_TRACKER.md)
3. [WINDOWS_INTEROP_LAB_PLAN.md](./WINDOWS_INTEROP_LAB_PLAN.md)
4. [DOCS_TO_CODE_MAPPING.md](./DOCS_TO_CODE_MAPPING.md)
5. [RISK_REGISTER.md](./RISK_REGISTER.md)

### Focus Areas
#### Focus Area 1: VM-Disk I/O Semantics
Questions to answer:
1. Why do flushes matter?
2. Why do sparse and zeroing semantics matter?
3. Why are ordinary file tests not enough for VHDX-backed workloads?

#### Focus Area 2: Leases and Oplocks
Questions to answer:
1. Why does client caching need coordination?
2. Why are breaks and reconnect paths high risk?
3. Why would a bug here hurt correctness and performance?

#### Focus Area 3: Support Matrix Thinking
Questions to answer:
1. What exactly is the Program A support claim?
2. Which filesystems are in the initial recommendation?
3. Why is the transport matrix kept narrow at first?

### Validation Exercises
#### Exercise 1: Turn a Bug Area Into a Test Idea
Choose one area:
1. reconnect
2. flush
3. sparse behavior
4. auth/session stability

Write down:
1. what the bug would look like from the client side
2. what a reproducer would need to do
3. what success would look like

#### Exercise 2: Turn a Support Claim Into a Matrix Slice
Pick one support statement and write:
1. Windows version
2. Hyper-V version
3. backing filesystem
4. auth mode
5. transport mode
6. workload type

This teaches the contributor that support claims are not slogans.

### Week 3 Goals
1. think in terms of proof, not just edits
2. understand that validation is part of implementation
3. connect code changes to support claims

### Deliverables by End of Week 3
1. one test-design note for a high-risk Program A area
2. one matrix slice written out explicitly
3. one paragraph explaining the highest-risk Program A subsystem in the contributor’s own words

### Good Mentor Checkpoint Questions
1. Which Program A subsystem seems riskiest and why?
2. What test would you write first for reconnect correctness?
3. Why is validation part of the feature, not separate from it?

## Week 4: Safe Contribution and Review Habits
Week 4 is the transition from learning to contributing.

### Good Starter Contribution Types
1. improve or clarify logging on a high-risk failure path
2. document an invariant in durable-handle or reconnect logic
3. add a support-boundary note where the code currently looks misleading
4. trace a path and write internal notes for the team
5. tighten a deliberate error return in an unsupported path
6. improve a small piece of validation scaffolding or test documentation

### Bad Starter Contribution Types
1. inventing new Program B features
2. changing RSVD behavior
3. changing failover semantics
4. changing transport security behavior without a strong review plan
5. changing write/flush semantics casually

### Review Habit Training
A junior contributor should learn to ask these questions before opening a patch:
1. Is this Program A scope or Program B scope?
2. Is the support claim already approved?
3. What invariant am I changing?
4. What is the failure mode if I am wrong?
5. What test or validation artifact would prove this change is safe?

### Week 4 Exercise: Starter Patch Proposal
Write a short patch proposal containing:
1. problem statement
2. files to touch
3. invariant affected
4. why the change is safe for a junior contributor to attempt
5. test or validation idea

### Week 4 Goals
1. make one bounded, reviewable contribution or patch proposal
2. demonstrate careful thinking about failure paths
3. show understanding of support boundaries

### Deliverables by End of Week 4
1. one safe patch proposal or one small merged improvement
2. one internal note explaining the affected invariant and why it matters
3. one suggested follow-up test or validation step

### Good Mentor Checkpoint Questions
1. Why is this patch small enough to be safe?
2. What invariant does it rely on?
3. What could go wrong if the patch is incomplete?
4. Why does this belong to Program A and not Program B?

## Recommended Ongoing Habits After Day 30
1. keep a personal glossary of terms and structures
2. write plain-English path summaries before modifying unfamiliar logic
3. reread `DECISION_PROPOSALS.md` whenever scope confusion appears
4. use `DOCS_TO_CODE_MAPPING.md` before guessing where to patch
5. treat reconnect, lease, lock, and flush changes as high risk by default

## Signs the Contributor Is Ready for Bigger Work
A junior contributor is ready for larger work when they can:
1. explain a full request path clearly
2. explain at least one reconnect path clearly
3. identify where state is stored and cleaned up
4. propose a test alongside a code change
5. distinguish Program A issues from Program B architecture work

## Warning Signs
A contributor still needs more onboarding if they:
1. treat support claims casually
2. think happy-path behavior is enough
3. cannot explain where state lives
4. want to start on RSVD, failover, or NTFS parity immediately
5. do not connect code changes to validation

## Recommended First 30-Day Output Bundle
By Day 30, a junior contributor should ideally have produced:
1. one or two plain-English trace notes
2. one matrix slice description
3. one test idea for a risky subsystem
4. one small patch or patch proposal
5. one short list of unresolved questions for the team

## Final Reminder
The goal of the first 30 days is not speed.
The goal is to become safe, useful, and difficult to confuse.

In this project, that matters more than rushing into code.
