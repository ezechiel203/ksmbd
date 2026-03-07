# B0-T2 NTFS Strategy Selection

Status: `planning`

## Purpose
Freeze the NTFS-visible behavior strategy before any parity implementation
starts.

## Primary Design Doc
1. `NTFS_BACKEND_ARCHITECTURE_OPTIONS.md`

## Required Outputs
1. Chosen architecture
2. Rejected architectures
3. Crash-consistency model

## Decision Candidates
1. Extend `ntfs3`
2. Metadata emulation layer
3. Dedicated NTFS-aware backend/service
4. Narrow claims only

## Exit Criteria
1. The chosen strategy has an owner, recovery model, and supportability story.
2. Unchosen strategies are rejected with reasons, not left ambiguous.
