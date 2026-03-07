# Mentor Checklist

## Purpose
This document helps a senior contributor or mentor evaluate a junior contributor’s onboarding progress against the project hub.

It is designed to pair with:
1. `NEW_CONTRIBUTOR_READING_PATH.md`
2. `FIRST_30_DAYS_ONBOARDING.md`
3. `PROGRAM_A_NARRATIVE_GUIDE.md`
4. `PROGRAM_B_NARRATIVE_GUIDE.md`

## How to Use This
Use this checklist at three points:
1. end of Week 1
2. end of Week 2 or 3
3. end of Day 30

Do not use it as a pass/fail test on trivia.
Use it to check whether the contributor is building:
1. a correct mental model
2. safe engineering habits
3. awareness of scope and support boundaries
4. the ability to work on bounded tasks without causing accidental scope drift

## Week 1 Checkpoint
### Goal
Verify that the contributor understands the project at a high level and is not confusing Program A with Program B.

### The contributor should be able to explain
1. what Program A is trying to ship
2. what Program B is trying to become
3. why Hyper-V-over-SMB is harder than ordinary file serving
4. why NTFS parity is a separate and larger problem
5. why the project uses narrow support claims

### Questions to Ask
1. What is the difference between Program A and Program B?
2. Why is Program A the real near-term target?
3. Why is Program B not automatically approved?
4. Why is a `.vhdx` file over SMB more dangerous than a normal document file?
5. Why are support claims tied to a matrix instead of intuition?

### Good Signs
1. the contributor uses the terms `Program A` and `Program B` correctly
2. the contributor understands that correctness beats breadth
3. the contributor can name the main project docs without guessing

### Warning Signs
1. the contributor talks about "Windows parity" as if it is already the goal
2. the contributor wants to start on RSVD, failover, or NTFS parity immediately
3. the contributor cannot explain the difference between Hyper-V support and NTFS parity

## Week 2-3 Checkpoint
### Goal
Verify that the contributor can trace state and connect docs to code.

### The contributor should be able to explain
1. where session handling roughly lives
2. where create/open logic roughly lives
3. where file state is tracked
4. where lease/oplock logic roughly lives
5. why durable/persistent handles matter

### Questions to Ask
1. Which files did you trace for session -> create -> read/write?
2. Where is open-file state tracked?
3. What makes reconnect logic dangerous?
4. Why do leases/oplocks matter to correctness and not just performance?
5. Which source files seem highest risk for Program A?

### Good Signs
1. the contributor can describe one request path in plain English
2. the contributor has written down invariants or cleanup concerns
3. the contributor uses `DOCS_TO_CODE_MAPPING.md` to orient themselves
4. the contributor distinguishes state ownership from transport behavior

### Warning Signs
1. the contributor only talks about syntax and not state transitions
2. the contributor cannot identify cleanup or failure paths
3. the contributor treats reconnect as a minor feature instead of a storage-safety issue

## Day 30 Checkpoint
### Goal
Verify that the contributor is ready for bounded implementation work.

### The contributor should be able to explain
1. the Program A critical path
2. the major Program A ship blockers
3. one or two traced request/state flows
4. what makes a contribution safe or unsafe for a junior developer
5. why validation is part of implementation

### Questions to Ask
1. What are the main Program A ship blockers?
2. Which subsystem currently looks highest risk to you and why?
3. What is one change you would consider safe for yourself to make now?
4. What change would you explicitly avoid right now and why?
5. What test or matrix slice would you want to see for your next contribution?

### Good Signs
1. the contributor proposes bounded work with explicit risks
2. the contributor talks about invariants, cleanup, and validation
3. the contributor can say "this is Program B work" when appropriate
4. the contributor understands that fake success is worse than honest `NOT_SUPPORTED`

### Warning Signs
1. the contributor still cannot distinguish Program A from Program B
2. the contributor wants to broaden support claims casually
3. the contributor proposes patches without a validation idea
4. the contributor is drawn to the biggest and riskiest code immediately

## Evaluation Areas
### 1. Scope Discipline
Assess whether the contributor:
1. understands support boundaries
2. avoids accidental scope expansion
3. uses the hub docs to ground decisions

### 2. State Reasoning
Assess whether the contributor:
1. can identify important state transitions
2. can reason about invariants
3. notices cleanup and lifetime risks

### 3. Validation Thinking
Assess whether the contributor:
1. links code changes to test ideas
2. understands why matrix-based support claims matter
3. thinks about client-visible failure modes

### 4. Code Navigation
Assess whether the contributor:
1. knows where major Program A logic lives
2. can use the hub to find the right subsystem
3. avoids random file exploration without a map

## Recommended First Tasks by Readiness
### If the contributor is still early
Assign:
1. path tracing notes
2. logging review
3. documentation clarifications
4. invariant writeups

### If the contributor is ready for a first safe patch
Assign:
1. error-path clarity improvement
2. targeted logging improvement
3. explicit unsupported-path cleanup
4. small validation or tooling support task

### If the contributor is not ready
Do not assign:
1. transport security changes
2. reconnect-state changes without close supervision
3. flush/write-ordering changes
4. RSVD, failover, or NTFS parity work

## Suggested Mentor Artifacts
A mentor should ideally collect:
1. the contributor’s plain-English trace notes
2. one matrix-slice writeup
3. one starter patch proposal
4. a list of unresolved questions the contributor still has

## Final Rule for Mentors
A junior contributor succeeding in this project does not look like:
- reading the most code the fastest

It looks like:
- building a correct mental model
- respecting scope and support claims
- making bounded, well-reasoned changes
