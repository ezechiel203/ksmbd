# Starter Task Templates

## Purpose
Provide simple, reusable templates for the kinds of artifacts junior contributors should produce during onboarding and early implementation work.

These templates are intentionally plain.
They are designed to reduce format noise and keep attention on correctness, scope, and validation.

## How to Use This File
Copy the relevant section into a new note, issue, review comment, or project document.

Recommended uses:
1. path tracing
2. patch proposals
3. support matrix slices
4. invariant notes
5. test ideas

## Template 1: Path Trace Note
Use this when tracing a request or state path through the code.

### Title
`Path Trace: <short path name>`

### Goal
What path am I tracing and why?

Example:
- trace durable handle reconnect from saved state to reopen

### Trigger
What starts this path?

Example:
- client sends durable reconnect request

### Main Files
1. `<file 1>`
2. `<file 2>`
3. `<file 3>`

### High-Level Flow
1. step one
2. step two
3. step three
4. step four

### Important State
1. which IDs matter?
2. which structures matter?
3. which flags or booleans matter?

### Failure Paths
1. what can fail early?
2. what can fail mid-path?
3. what cleanup must happen?

### Invariants I Think Matter
1. invariant one
2. invariant two
3. invariant three

### Questions I Still Have
1. question one
2. question two

## Template 2: Starter Patch Proposal
Use this before making a code change.

### Title
`Patch Proposal: <short name>`

### Problem Statement
What is wrong, unclear, or risky right now?

### Scope
Is this:
1. Program A
2. Program B planning only
3. cross-cutting documentation/validation work

### Files I Expect to Touch
1. `<file 1>`
2. `<file 2>`

### Why This Is Safe for a Starter Task
1. narrow scope
2. low semantic risk
3. easy to review

### What Must Not Change
1. invariant one
2. supported behavior one
3. support boundary one

### Proposed Change
1. change one
2. change two

### Validation Idea
1. what would I check after the patch?
2. what log, test, or behavior should improve?

### Risks
1. possible misunderstanding of path
2. possible wrong error mapping
3. possible stale comment assumptions

### Review Questions
1. Is the support boundary still correct?
2. Did I accidentally change semantics instead of clarifying them?

## Template 3: Support Matrix Slice
Use this when describing one explicit supported or tested scenario.

### Title
`Matrix Slice: <short name>`

### Windows Side
1. Windows Server version:
2. Hyper-V version:
3. domain-joined or local auth:

### Linux Side
1. kernel version:
2. ksmbd build identity:
3. backing filesystem:
4. mount options if relevant:

### Transport
1. TCP / QUIC / RDMA:
2. signing enabled:
3. encryption enabled:

### Workload
1. VM create:
2. boot from VHDX:
3. sustained I/O:
4. checkpoint/merge:
5. reconnect under load:

### Result
1. pass / fail / blocked
2. known caveats:

### Logs / Artifacts
1. where results are stored:

## Template 4: Invariant Note
Use this when documenting a fragile or important assumption in code or planning.

### Title
`Invariant: <short name>`

### Context
Which path or subsystem does this invariant belong to?

### Statement
What must remain true?

Example:
- restored persistent handles must not delete saved state before successful reopen

### Why It Matters
1. what breaks if it is violated?
2. is the risk data integrity, reconnect correctness, auth correctness, or support-boundary confusion?

### Where It Lives
1. `<file 1>`
2. `<function 1>`
3. `<related doc>`

### Failure Symptoms
1. symptom one
2. symptom two

### Validation Idea
How would we notice if this invariant breaks?

## Template 5: Test Idea Note
Use this when turning a risky subsystem into a concrete validation idea.

### Title
`Test Idea: <short name>`

### Risk Area
What subsystem or behavior is this meant to validate?

### Why It Matters
Why would failure here hurt Program A or Program B?

### Preconditions
1. environment
2. auth mode
3. filesystem
4. transport

### Steps
1. step one
2. step two
3. step three

### Expected Result
1. expected client-visible behavior
2. expected server-side behavior

### Failure Signals
1. wrong status
2. reconnect fails
3. stale state remains
4. data mismatch
5. unexpected log pattern

## Template 6: Mentor Review Note
Use this when reviewing a junior contributor’s early work.

### Title
`Mentor Review: <artifact name>`

### What Was Good
1. point one
2. point two

### What Needs Correction
1. point one
2. point two

### Scope Check
Did the contributor stay inside the intended program and support boundary?

### Risk Check
Did the contributor identify the real failure risk?

### Next Best Task
What should they do next?

## Template 7: Open Question Note
Use this when a contributor finds something unclear and wants to escalate cleanly.

### Title
`Open Question: <short name>`

### Context
What file, path, or feature area is this about?

### What I Observed
1. observation one
2. observation two

### Why I Am Unsure
1. uncertainty one
2. uncertainty two

### My Best Guess
What do I think might be true?

### What I Need From Review
1. confirm intended behavior
2. confirm support boundary
3. confirm whether this is Program A or Program B work

## Recommendation
Use these templates by default for junior onboarding work.

They make reviews faster, reduce ambiguity, and help contributors learn to think in terms of:
1. scope
2. invariants
3. risk
4. validation
