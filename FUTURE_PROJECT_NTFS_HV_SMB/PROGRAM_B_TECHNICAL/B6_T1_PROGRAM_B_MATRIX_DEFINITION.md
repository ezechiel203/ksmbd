# B6-T1 Program B Matrix Definition

Status: `planning`

## Purpose
Define the release-qualification matrix for the exact Program B features that
make it through architecture approval.

## Required Outputs
1. Version matrix
2. Transport matrix
3. Filesystem matrix
4. Cluster matrix if claimed
5. RSVD matrix if claimed

## Matrix Rule
Every public claim must map to a named matrix row, and every matrix row must
name the feature branch it exercises: NTFS, RSVD/VHDX, failover, or a combined
subset.

## Exit Criteria
1. The published support statement is a strict subset of this matrix.
