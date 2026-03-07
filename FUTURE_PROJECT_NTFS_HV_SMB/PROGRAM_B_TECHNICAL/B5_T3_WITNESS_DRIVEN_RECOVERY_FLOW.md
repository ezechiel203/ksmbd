# B5-T3 Witness-Driven Recovery Flow

Status: `planning`

## Purpose
Document the exact recovery path, and the unsupported paths, for any
witness-driven failover claim.

## Required Outputs
1. Claimed recovery path
2. Unsupported failover path list

## Recovery Questions
1. Which event triggers witness guidance
2. What state must already be durable/shared
3. How clients rebind and what errors are acceptable
4. Which timing windows remain unsupported

## Exit Criteria
1. The witness story is narrower than the lab-validated matrix.
