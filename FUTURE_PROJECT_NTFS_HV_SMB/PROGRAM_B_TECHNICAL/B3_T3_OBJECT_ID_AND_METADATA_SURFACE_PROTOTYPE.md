# B3-T3 Object ID and Metadata Surface Prototype

Status: `planning`

## Purpose
Prototype the metadata surface needed for object IDs and adjacent NTFS-visible
metadata behaviors.

## Required Outputs
1. Metadata storage strategy
2. Admin/workflow tests

## Design Questions
1. Where metadata lives
2. How metadata survives rename and restore
3. How backup/restore and repair behave
4. Which admin tools or Windows workflows depend on the feature

## Exit Criteria
1. Object ID support is either made defensible or explicitly rejected.
