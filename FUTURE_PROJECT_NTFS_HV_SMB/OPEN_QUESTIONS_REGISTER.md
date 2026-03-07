# Open Questions Register

## Purpose
Track unresolved technical and product questions separately from formal decisions.

Use this file for questions that are still being investigated.
Use `DECISION_LOG.md` for decisions that are already proposed or approved.

## How to Use This
Each question should record:
1. question ID
2. topic area
3. question
4. why it matters
5. current best hypothesis
6. what evidence is needed
7. owner
8. target date

## Questions
### Q-001
Topic area:
- Program A transport scope

Question:
- Should QUIC enter the supported matrix immediately after the first TCP-only Program A release, or only after a separate interop cycle?

Why it matters:
- affects transport roadmap, lab scope, and support claims

Current best hypothesis:
- QUIC should remain post-release until a dedicated interop cycle passes

What evidence is needed:
1. strict-client QUIC interop results
2. operational stability results
3. review of any remaining QUIC-specific TODOs

Owner:
- transport lead

Target date:
- before planning Program A.1

### Q-002
Topic area:
- Program A filesystem matrix

Question:
- After `xfs` and `ext4`, which filesystem should be evaluated next, if any?

Why it matters:
- expands or constrains future support matrix scope

Current best hypothesis:
- `btrfs` is the most likely next candidate, but only after Program A baseline is stable

What evidence is needed:
1. workload stability comparison
2. sparse/zeroing behavior comparison
3. operational failure-mode review

Owner:
- storage/filesystem lead

Target date:
- after Program A A3

### Q-003
Topic area:
- Auth and operations

Question:
- Is domain-backed auth mandatory for every supported Program A deployment, or can there be a supported local-auth subset?

Why it matters:
- changes support claim and testing requirements

Current best hypothesis:
- domain-backed auth should be the main supported path for Hyper-V-oriented deployments, with local auth possibly documented as narrower support

What evidence is needed:
1. customer requirements
2. operational tradeoff review
3. auth-lab stability comparison

Owner:
- auth/session lead

Target date:
- before A0 exits fully

### Q-004
Topic area:
- Program B approval

Question:
- What specific product requirement would justify activating Program B rather than stopping at Program A?

Why it matters:
- prevents speculative multi-year scope expansion

Current best hypothesis:
- Program B should require explicit customer demand for more than standalone Hyper-V-over-SMB support

What evidence is needed:
1. customer/use-case statements
2. revenue or strategic justification
3. staffing commitment

Owner:
- product owner / technical lead

Target date:
- at Program A A3 review

### Q-005
Topic area:
- NTFS architecture

Question:
- If Program B is approved, which NTFS-visible features are truly required first: short names, compression control, object IDs, quotas, or something else?

Why it matters:
- affects architecture choice and avoids solving the wrong NTFS problem first

Current best hypothesis:
- short names and selected metadata visibility would likely matter before broader NTFS parity items

What evidence is needed:
1. real client/workflow requirements
2. admin-tool compatibility goals
3. architecture feasibility comparison

Owner:
- filesystem architecture lead

Target date:
- within 30 days of Program B approval

### Q-006
Topic area:
- RSVD scope

Question:
- Which exact Hyper-V shared-disk workflows would be required if RSVD ever enters scope?

Why it matters:
- prevents vague RSVD commitments

Current best hypothesis:
- no RSVD work should begin until one exact workflow is named and bounded

What evidence is needed:
1. scenario description
2. required command coverage
3. validation plan

Owner:
- virtual disk / RSVD lead

Target date:
- only if Program B approval discussion starts

### Q-007
Topic area:
- Failover claims

Question:
- Would a bounded failover/recovery model be enough for future product goals, or is true cluster-grade behavior actually required?

Why it matters:
- dramatically changes state-model and lab complexity

Current best hypothesis:
- bounded failover would be more realistic than full cluster-grade parity, if failover is needed at all

What evidence is needed:
1. product requirements
2. cluster scenario requirements
3. architecture cost estimate

Owner:
- cluster/availability lead

Target date:
- only after Program A proves value

## Notes
1. Questions in this file can later become entries in `DECISION_PROPOSALS.md`.
2. Once a question has a proposed answer and concrete direction, it should move into `DECISION_LOG.md`.
