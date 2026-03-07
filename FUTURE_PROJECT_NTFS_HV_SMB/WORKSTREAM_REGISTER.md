# Workstream Register

## Purpose
Provide a one-page register of major workstreams, owners, and dependencies.

## Workstreams
### W1 Transport and Crypto
Program:
- A and B

Primary areas:
- `src/transport/`
- `src/core/`

Dependencies:
- interoperability lab

### W2 Durable State and Reconnect
Program:
- A and B

Primary areas:
- `src/protocol/smb2/`
- `src/fs/`

Dependencies:
- transport stability
- fault-injection tests

### W3 VM-Disk Semantics
Program:
- A and B

Primary areas:
- `src/fs/`
- `src/protocol/smb2/`

Dependencies:
- durable state and reconnect
- Hyper-V workload lab

### W4 Auth and Sessioning
Program:
- A and B

Primary areas:
- `src/protocol/smb2/`
- `ksmbd-tools/`

Dependencies:
- domain lab

### W5 Observability and Operations
Program:
- A and B

Primary areas:
- `src/core/`
- `src/mgmt/`
- `ksmbd-tools/`

Dependencies:
- metrics and release engineering

### W6 NTFS Compatibility
Program:
- B only

Primary areas:
- architecture-dependent

Dependencies:
- NTFS strategy decision

### W7 RSVD/VHDX Platform
Program:
- B only

Primary areas:
- `src/fs/ksmbd_rsvd.c`
- future backend code

Dependencies:
- VHDX backend strategy
- Hyper-V shared-disk lab

### W8 Multichannel, Witness, Failover
Program:
- B only

Primary areas:
- `src/core/`
- `src/protocol/smb2/`
- `src/mgmt/ksmbd_witness.*`

Dependencies:
- cluster state model
- multi-NIC and failover lab

### W9 Release Qualification
Program:
- A and B

Primary areas:
- future `tests/`
- lab automation
- release process

Dependencies:
- all other workstreams
