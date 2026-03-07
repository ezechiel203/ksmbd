# Decision Proposals

## Purpose
Turn the open questions in `DECISION_LOG.md` into precise proposed decisions with recommended answers, rationale, consequences, and validation implications.

## Decision Format
Each decision records:
1. decision ID
2. question
3. recommended answer
4. rationale
5. consequences
6. required follow-up work
7. decision deadline

## D-001
### Question
Is Program A TCP-only at first release, or does it include QUIC?

### Recommended Answer
Program A first release should be `TCP-only`.

### Rationale
1. TCP is already the normal baseline for Hyper-V over SMB deployments.
2. QUIC is valuable, but it is not required to prove Program A.
3. QUIC still carries transport-specific correctness risk and additional interop burden.
4. Shipping Program A on TCP first reduces schedule risk and makes the support claim clearer.

### Consequences
1. QUIC remains a post-Program-A enhancement unless explicitly accelerated.
2. Program A lab can focus on SMB semantics and VM-disk behavior first.
3. Transport-hardening work for QUIC can continue in parallel without blocking the first product claim.

### Required Follow-Up Work
1. Mark QUIC as `deferred from Program A release claim` in support docs.
2. Keep QUIC in A-01 as a parallel hardening stream if resources allow.
3. Add a later decision point for whether QUIC enters the supported matrix in Program A.1 or Program B.

### Decision Deadline
Before A0 exits.

## D-002
### Question
Is SMB Direct part of Program A or deferred?

### Recommended Answer
SMB Direct should be `deferred` from Program A.

### Rationale
1. SMB Direct is not required for a credible first Hyper-V-over-SMB product.
2. RDMA security and transport validation are more specialized and hardware-dependent.
3. Including SMB Direct in Program A would multiply lab and support complexity.
4. Program A should prove correctness before it chases transport breadth.

### Consequences
1. Program A support claim excludes SMB Direct.
2. RDMA work becomes either late Program A.1 or Program B foundation work.
3. The first supported matrix remains cheaper to validate and easier to operate.

### Required Follow-Up Work
1. State explicitly that SMB Direct is unsupported in Program A.
2. Keep RDMA transform-security work in backlog, not in release gating.
3. Define hardware requirements if SMB Direct is reintroduced later.

### Decision Deadline
Before A0 exits.

## D-003
### Question
Which backing filesystems are in the initial supported matrix for Program A?

### Recommended Answer
Initial Program A support should be limited to:
1. `xfs`
2. `ext4`

`btrfs`, `ntfs3`, and other filesystems should be excluded from the first supported matrix.

### Rationale
1. `xfs` and `ext4` are the most conventional choices for stable Linux file-serving deployments.
2. `btrfs` introduces extra semantics and failure/performance variability that expands test cost.
3. `ntfs3` would blur Program A into NTFS-compatibility territory prematurely.
4. A narrow backing-FS set makes VM-disk behavior easier to validate and support.

### Consequences
1. Support claims become much clearer.
2. Program A test matrix stays bounded.
3. NTFS parity work remains isolated to Program B decisions.

### Required Follow-Up Work
1. Add `xfs` and `ext4` to the Program A matrix in lab docs.
2. Explicitly list `btrfs`, `ntfs3`, and FUSE-backed filesystems as unsupported for the first release.
3. Build filesystem-specific VM-disk stress tests for `xfs` and `ext4`.

### Decision Deadline
Before A0 exits.

## D-004
### Question
Is Program B a real approved program, or only a future option?

### Recommended Answer
Program B should remain a `future option` until Program A reaches A3 successfully.

### Rationale
1. Program A already delivers significant value if executed well.
2. Program B is too large to approve responsibly before Program A proves market and technical value.
3. Program B depends on architectural decisions and a lab footprint that should not be funded speculatively without product pull.

### Consequences
1. No Program B implementation should begin yet.
2. Only Program B planning, feasibility, and architecture evaluation should continue.
3. Team staffing and scope remain realistic.

### Required Follow-Up Work
1. Freeze Program B as `planning only` in governance docs.
2. Revisit approval after Program A milestone A3.
3. Require an explicit approval memo before any Program B code work starts.

### Decision Deadline
At the end of A3, not before.

## D-005
### Question
If Program B exists, which NTFS strategy is chosen?

### Recommended Answer
The recommended priority order is:
1. `Option 4` narrow claims only, unless Program B is truly approved
2. if Program B is approved and NTFS-visible features are required, evaluate `Option 2` metadata emulation first for selected features
3. only choose `Option 1` extending `ntfs3` if the product explicitly commits to deep NTFS parity and can staff kernel/filesystem work

### Rationale
1. Extending `ntfs3` is technically strong but organizationally expensive.
2. A metadata emulation layer may deliver selected Windows-visible behavior faster, but only if claim boundaries stay narrow.
3. A dedicated NTFS-aware backend is too large to select without strong product justification.

### Consequences
1. There is no immediate NTFS architecture decision while Program B is unapproved.
2. If Program B activates, the first real architecture study should compare `Option 2` and `Option 1` against concrete product requirements.
3. Full NTFS parity should not be promised by default.

### Required Follow-Up Work
1. Produce a sharper feature-to-architecture table if Program B is approved.
2. Prototype metadata-emulation failure modes before adopting that path.
3. Refuse any parity claim until one architecture is frozen.

### Decision Deadline
Within 30 days of Program B approval.

## D-006
### Question
Is RSVD in scope, and for which exact workflows?

### Recommended Answer
RSVD should be `out of scope` for Program A and `unapproved` for Program B until a customer or product requirement names exact workflows.

If Program B later approves RSVD, the first supported workflow should be only:
1. one bounded Hyper-V shared-disk scenario
2. no blanket claim of broad shared-disk parity

### Rationale
1. RSVD is specialized storage work, not ordinary SMB feature work.
2. It requires backend ownership, reservation semantics, and dedicated validation.
3. Broad RSVD scope would destabilize priorities before basic Hyper-V-over-SMB support is shipped.

### Consequences
1. `ksmbd_rsvd.c` remains non-productized for now.
2. Shared-disk Hyper-V scenarios are explicitly unsupported.
3. Any future RSVD effort must start from a bounded scenario statement.

### Required Follow-Up Work
1. Capture exact requested workflows before revisiting RSVD.
2. Do not allow generic “Hyper-V parity” language to imply RSVD support.
3. If revisited, produce a scenario document before any implementation.

### Decision Deadline
Program A: fixed now as out of scope.
Program B: only after a concrete product requirement appears.

## D-007
### Question
Is cluster-grade failover a real product goal or not?

### Recommended Answer
For now, `no`.

The project should target:
1. standalone or bounded reconnect semantics in Program A
2. re-evaluate bounded failover only after Program A success
3. defer any true cluster-grade claim until a shared-state model and lab exist

### Rationale
1. Cluster-grade failover is a state-platform problem, not a small protocol feature.
2. It requires witness, shared or replicated state, failover testing, and negative-path handling.
3. Approving it too early would blur the project into a much larger platform effort.

### Consequences
1. Program A remains operationally realistic.
2. Program B planning can still evaluate cluster possibilities without committing engineering prematurely.
3. Any failover language in future docs must stay bounded and explicit.

### Required Follow-Up Work
1. Keep `CLUSTER_FAILOVER_STATE_MODEL.md` as planning only.
2. Refuse cluster-grade support claims without explicit approval and lab proof.
3. Revisit only after Program A reaches A3 and market pull is clear.

### Decision Deadline
Program A: fixed now as no.
Program B: only after explicit product review.

## Summary of Recommended Immediate Decisions
Recommended to lock now:
1. D-001: TCP-only for Program A first release
2. D-002: SMB Direct deferred
3. D-003: `xfs` and `ext4` only for the first supported matrix
4. D-006: RSVD out of scope for Program A
5. D-007: no cluster-grade goal for Program A

Recommended to defer intentionally:
1. D-004: Program B approval until after A3
2. D-005: NTFS architecture until Program B approval
