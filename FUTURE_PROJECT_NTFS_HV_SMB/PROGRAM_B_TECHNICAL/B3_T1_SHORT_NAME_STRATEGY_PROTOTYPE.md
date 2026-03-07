# B3-T1 Short Name Strategy Prototype

Status: `planning`

## Purpose
Prototype how 8.3-style short names would be stored, generated, and updated if
Program B chooses to support them for any scope.

## Potential Code Areas
1. `src/fs/`
2. `src/protocol/smb2/`
3. Architecture-dependent metadata layer

## Required Outputs
1. Exact storage model
2. Generation policy
3. Rename/update semantics

## Constraints
1. Must define collision handling
2. Must define rename/link/delete atomicity
3. Must not imply continuous-availability compatibility where Windows itself
   does not support it

## Exit Criteria
1. The prototype yields a clear support/no-support decision.
