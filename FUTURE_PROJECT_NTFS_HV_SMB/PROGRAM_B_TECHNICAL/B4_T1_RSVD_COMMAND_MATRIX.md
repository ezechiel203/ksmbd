# B4-T1 RSVD Command Matrix

Status: `planning`

## Purpose
List exactly which RSVD commands would be handled, rejected, or deferred.

## Primary Code Area
1. `src/fs/ksmbd_rsvd.c`

## Required Outputs
1. Allowed command matrix
2. Unsupported command matrix
3. Error mapping

## Matrix Rules
1. Every supported command must name the target workflow.
2. Unsupported commands must map to deliberate status results.
3. Command scope must match the chosen backend model.

## Exit Criteria
1. No RSVD coding begins without this matrix frozen.
