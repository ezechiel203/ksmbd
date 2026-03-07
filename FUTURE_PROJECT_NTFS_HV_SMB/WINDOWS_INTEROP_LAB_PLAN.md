# Windows Interoperability Lab Plan

## Purpose
Define the lab needed to validate any support claim made by this project.

## Principle
No support claim is real until it has a passing slice in the Windows interoperability lab.

## Lab Tracks
1. Program A track: standalone Hyper-V over SMB
2. Program B track: broader Windows/NTFS/cluster/RSVD parity

## Baseline Environment
### Linux Side
1. dedicated SMB server hosts
2. reproducible kernel and userspace build artifacts
3. multiple backing filesystem configurations
4. fault-injection capability
5. metrics and log collection

### Windows Side
1. at least two Windows Server versions
2. at least two Hyper-V host versions if supported matrix spans them
3. domain-backed environment
4. representative VM templates
5. automation-friendly host provisioning

## Environment Matrix
### Program A Minimum Matrix
1. Windows Server N and N-1
2. one domain-backed environment
3. one or two Linux filesystems
4. TCP mandatory
5. QUIC optional
6. SMB Direct optional later

### Program B Expanded Matrix
1. broader Windows Server matrix
2. clustered scenarios if claimed
3. witness/multichannel matrix
4. RSVD/shared-disk matrix if claimed
5. NTFS metadata/admin workflow matrix if claimed

## Test Families
### 1. Functional SMB Tests
1. create/open/close/delete/rename
2. metadata query/set
3. security descriptor paths
4. share-mode and lock conflicts

### 2. Hyper-V VM-Disk Tests
1. create VHDX on share
2. attach VHDX to VM
3. boot guest from share-hosted VHDX
4. sustained guest I/O
5. checkpoint and merge
6. host reconnect during guest load

### 3. Durability and Recovery Tests
1. network interruption
2. SMB service restart
3. host-side restart during disconnected durable window
4. backing-filesystem unclean shutdown and recovery checks

### 4. Authentication Tests
1. domain auth
2. ticket refresh
3. invalid credentials
4. clock skew
5. userspace daemon unavailability

### 5. Transport Tests
1. TCP baseline
2. QUIC if enabled
3. RDMA if enabled
4. encryption/signing on each supported transport

### 6. Soak and Stress Tests
1. 24h+ guest workload soak
2. boot storm
3. mixed VM density and mixed I/O profile
4. reconnect storm after network flap

### 7. Program B Additional Tests
1. multichannel and failover
2. witness notifications
3. RSVD/shared-disk conflicts
4. Windows admin-tool metadata workflows
5. cluster failover if claimed

## Lab Automation Requirements
1. environment provisioning scripts
2. repeatable share creation and configuration
3. Windows-side test orchestration
4. standardized log collection
5. artifact retention for failures
6. pass/fail dashboards by matrix slice

## Release Gating Rules
1. Every release candidate must run the Program A matrix if Program A is supported.
2. Every Program B claim must have a dedicated gating matrix.
3. Known-failure slices must block any claim that depends on them.
4. No unsupported matrix cell may be described as "expected to work".

## Minimum Artifacts Per Test Run
1. server build identity
2. kernel version and config
3. filesystem type and options
4. Windows build identity
5. transport mode
6. auth mode
7. pass/fail result
8. logs and metrics bundle

## Ownership
1. validation lead owns the lab
2. subsystem owners own failed slices touching their area
3. release owner owns the final support matrix publication

## Recommendation
Build the Program A lab first and treat it as non-optional. Program B must not start making broad claims until the expanded lab exists.
