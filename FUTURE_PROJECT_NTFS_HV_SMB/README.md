# Future Project Hub: NTFS + Hyper-V + SMB

Quick audience index:
- [PROJECT_INDEX.md](./PROJECT_INDEX.md)

This directory is the control center for the future Windows-compatibility project.

Its purpose is to keep strategy, architecture, scope control, execution planning, and claim boundaries in one place instead of scattering them across review notes and ad hoc conversations.

## Start Here
1. [MEGAPLAN_WINDOWS_PARITY.md](./MEGAPLAN_WINDOWS_PARITY.md)
   - full strategic roadmap
   - Program A: minimum Hyper-V over SMB
   - Program B: maximum Windows Server SMB + NTFS + Hyper-V parity
2. [IMPLEMENTATION_BOARD.md](./IMPLEMENTATION_BOARD.md)
   - execution-facing board across both programs
3. [DECISION_PROPOSALS.md](./DECISION_PROPOSALS.md)
   - precise proposed answers for the major open project decisions
4. [DOCS_TO_CODE_MAPPING.md](./DOCS_TO_CODE_MAPPING.md)
   - maps roadmap items to exact source files and suggested patch order

## New Contributor Onboarding
1. [NEW_CONTRIBUTOR_READING_PATH.md](./NEW_CONTRIBUTOR_READING_PATH.md)
   - one week day-by-day reading plan across both Program A and Program B for junior contributors
2. [FIRST_30_DAYS_ONBOARDING.md](./FIRST_30_DAYS_ONBOARDING.md)
   - a full first-month onboarding plan with reading, tracing, validation habits, and safe starter contribution guidance
3. [PROGRAM_A_NARRATIVE_GUIDE.md](./PROGRAM_A_NARRATIVE_GUIDE.md)
   - a large beginner-friendly explanation of Program A, safe Hyper-V-over-SMB scope, the key code paths, and how to approach implementation without getting lost
4. [PROGRAM_B_NARRATIVE_GUIDE.md](./PROGRAM_B_NARRATIVE_GUIDE.md)
   - a large beginner-friendly explanation of what Program B is, why it is hard, how the codebase is organized, and how to approach implementation safely

## Program Execution
1. [A_PROGRAM_MILESTONE_BOARD.md](./A_PROGRAM_MILESTONE_BOARD.md)
   - milestone-level delivery plan for Program A
2. [A_PROGRAM_TASK_TRACKER.md](./A_PROGRAM_TASK_TRACKER.md)
   - concrete task packages and critical path for Program A
3. [B_PROGRAM_FEASIBILITY_DECISION.md](./B_PROGRAM_FEASIBILITY_DECISION.md)
   - explicit go/no-go framework for Program B
4. [B_PROGRAM_TASK_TRACKER.md](./B_PROGRAM_TASK_TRACKER.md)
   - planning-level task packages for Program B if approved

## Technical Artifact Sets
1. [PROGRAM_A_TECHNICAL/README.md](./PROGRAM_A_TECHNICAL/README.md)
   - task-level technical files for every Program A tracker item
2. [PROGRAM_B_TECHNICAL/README.md](./PROGRAM_B_TECHNICAL/README.md)
   - task-level technical files for every Program B tracker item

## Architecture and Product Decisions
1. [NTFS_BACKEND_ARCHITECTURE_OPTIONS.md](./NTFS_BACKEND_ARCHITECTURE_OPTIONS.md)
   - options for any NTFS-visible compatibility strategy
2. [RSVD_VHDX_BACKEND_REQUIREMENTS.md](./RSVD_VHDX_BACKEND_REQUIREMENTS.md)
   - what is required to support RSVD/shared-disk workflows
3. [CLUSTER_FAILOVER_STATE_MODEL.md](./CLUSTER_FAILOVER_STATE_MODEL.md)
   - state-management model needed for any failover claim
4. [PROGRAM_B_RELEASE_CLAIMS.md](./PROGRAM_B_RELEASE_CLAIMS.md)
   - claim-control policy for Program B

## Open Questions
1. [OPEN_QUESTIONS_REGISTER.md](./OPEN_QUESTIONS_REGISTER.md)
   - unresolved technical and product questions that still need evidence before they become formal decisions

## Project Control
1. [DECISION_LOG.md](./DECISION_LOG.md)
   - durable record of major project decisions
2. [RISK_REGISTER.md](./RISK_REGISTER.md)
   - strategic and execution risks
3. [WORKSTREAM_REGISTER.md](./WORKSTREAM_REGISTER.md)
   - one-page list of workstreams and dependencies
4. [DELIVERY_SEQUENCE.md](./DELIVERY_SEQUENCE.md)
   - pragmatic execution order
5. [GOVERNANCE.md](./GOVERNANCE.md)
   - rules for using and updating this hub

## Validation and Qualification
1. [WINDOWS_INTEROP_LAB_PLAN.md](./WINDOWS_INTEROP_LAB_PLAN.md)
   - Windows/Hyper-V lab plan and release-gating model

## Contributor Templates
1. [STARTER_TASK_TEMPLATES.md](./STARTER_TASK_TEMPLATES.md)
   - copyable templates for path traces, patch proposals, matrix slices, invariant notes, test ideas, and mentor reviews

## Starter Work
1. [STARTER_TASK_CATALOG.md](./STARTER_TASK_CATALOG.md)
   - safe first contributions for junior developers, with exact files, risk level, and why each task is appropriate

## Mentoring
1. [MENTOR_CHECKLIST.md](./MENTOR_CHECKLIST.md)
   - structured checkpoints for reviewing a junior contributor's first week, first month, and readiness for safe implementation work

## Support Files
1. [GLOSSARY.md](./GLOSSARY.md)
   - terms used across this hub

## Reading Paths
### If the goal is to ship something real soon
1. `MEGAPLAN_WINDOWS_PARITY.md`
2. `DECISION_PROPOSALS.md`
3. `A_PROGRAM_MILESTONE_BOARD.md`
4. `A_PROGRAM_TASK_TRACKER.md`
5. `DOCS_TO_CODE_MAPPING.md`
6. `WINDOWS_INTEROP_LAB_PLAN.md`

### If the goal is to decide whether Program B should exist at all
1. `MEGAPLAN_WINDOWS_PARITY.md`
2. `B_PROGRAM_FEASIBILITY_DECISION.md`
3. `NTFS_BACKEND_ARCHITECTURE_OPTIONS.md`
4. `RSVD_VHDX_BACKEND_REQUIREMENTS.md`
5. `CLUSTER_FAILOVER_STATE_MODEL.md`
6. `PROGRAM_B_RELEASE_CLAIMS.md`

### If the goal is to start implementation planning
1. `DECISION_PROPOSALS.md`
2. `DOCS_TO_CODE_MAPPING.md`
3. `A_PROGRAM_TASK_TRACKER.md`
4. `B_PROGRAM_TASK_TRACKER.md`
5. `WORKSTREAM_REGISTER.md`

### If the goal is governance and scope control
1. `PROGRAM_B_RELEASE_CLAIMS.md`
2. `DECISION_LOG.md`
3. `RISK_REGISTER.md`
4. `GOVERNANCE.md`

## Immediate Recommended Decisions
1. Program A first release should be TCP-only.
2. SMB Direct should be deferred from Program A.
3. `xfs` and `ext4` should be the only initial supported backing filesystems.
4. Program B should remain unapproved until Program A reaches A3 successfully.
5. RSVD should stay out of scope for Program A.
6. Cluster-grade failover should not be a Program A goal.

## Relationship to Review Artifacts
The source review context remains in:
- [../GPTREVIEW_060326/README.md](../GPTREVIEW_060326/README.md)

This directory is where that review context turns into future-project planning and execution.
