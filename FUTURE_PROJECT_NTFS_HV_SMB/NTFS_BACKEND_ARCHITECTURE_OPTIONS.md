# NTFS Backend Architecture Options

## Purpose
This document evaluates the architectural choices for any Program B work that claims NTFS-visible compatibility beyond what current Linux filesystem interfaces already provide.

## Problem Statement
Several Windows-visible behaviors identified in the review and roadmap are not cleanly available through current Linux VFS abstractions alone:
1. short names
2. compression set semantics
3. object IDs
4. quota semantics that look like NTFS to Windows clients
5. USN-like change journal behavior
6. selected namespace and metadata semantics

If the project wants to claim these features, it must choose an architecture rather than adding one-off shims.

## Non-Negotiable Constraints
1. Crash consistency must be defined.
2. Behavior must be testable against Windows clients.
3. Unsupported features must fail deliberately, not silently degrade.
4. The support burden must be sustainable.
5. The design must not quietly fork Linux VFS semantics without owning the consequences.

## Option 1: Extend `ntfs3`
### Description
Add missing NTFS-visible behaviors to the in-kernel `ntfs3` driver and let `ksmbd` consume them through stable VFS/xattr/ioctl interfaces.

### What this could enable
1. better NTFS metadata fidelity
2. possible support for short-name accessors
3. possible compression-control plumbing
4. possible object-ID or journal surface if explicitly implemented

### Advantages
1. closest to the actual filesystem semantics
2. no split brain between SMB metadata layer and on-disk state
3. better long-term correctness if the upstream filesystem is improved properly

### Disadvantages
1. very high kernel/filesystem engineering cost
2. upstreamability and maintenance burden are substantial
3. still may not cover every Windows semantic cleanly
4. expands scope outside the `ksmbd` repo and team

### Fit
1. technically strongest for true NTFS parity
2. organizationally hardest

### Verdict
Best long-term option if full NTFS parity is a true product requirement and the project is willing to invest in filesystem engineering.

## Option 2: Metadata Emulation Layer in or alongside `ksmbd`
### Description
Keep Linux filesystems as they are, but layer Windows/NTFS-visible metadata and behavior in a sidecar metadata store or internal emulation layer that `ksmbd` consults.

### What this could enable
1. short-name generation and lookup independent of filesystem support
2. object IDs
3. synthetic quota or metadata behavior
4. selective Windows-like namespace behavior
5. potentially a change journal abstraction

### Advantages
1. keeps most work near the SMB server domain
2. can work across multiple Linux filesystems
3. support claims can be scoped feature-by-feature
4. easier to iterate than deep filesystem work

### Disadvantages
1. high risk of semantic drift from underlying filesystem reality
2. crash consistency becomes a major design problem
3. rename/link/delete corner cases become difficult
4. backup, restore, and repair tooling become part of the product burden
5. risk of creating a Windows-metadata database with weak durability semantics

### Fit
1. strong for selective compatibility features
2. risky for features tightly coupled to true filesystem behavior

### Verdict
Best option if the project wants selected Windows-visible metadata features without taking ownership of a full NTFS filesystem implementation. Requires very strong discipline around claim boundaries and recovery semantics.

## Option 3: Dedicated NTFS-Aware Backend or Service
### Description
Introduce a separate backend that is explicitly NTFS-aware and exposes the required semantics to `ksmbd`, potentially as a dedicated service, library, or storage layer.

### What this could enable
1. richer NTFS behavior than plain VFS access
2. possible coexistence with specialized virtual-disk or metadata logic
3. tighter control over compatibility semantics

### Advantages
1. avoids bending generic Linux filesystems into Windows semantics
2. allows a more explicit product boundary around Windows-compatible storage
3. can evolve independently from core `ksmbd` logic

### Disadvantages
1. this is effectively a new storage platform
2. operational complexity increases sharply
3. deployment, support, observability, and failure handling become much harder
4. testing matrix multiplies

### Fit
1. strongest for a strategic Windows-compatible storage product
2. excessive for ordinary SMB server goals

### Verdict
Appropriate only if the project explicitly chooses to become a Windows-compatible storage platform. Not justified for a narrow Hyper-V-over-SMB target.

## Option 4: Stay with Existing Linux Filesystems and Narrow Claims
### Description
Do not implement NTFS parity beyond what current filesystems and VFS semantics already support. Expose only what is real and deliberately return not-supported elsewhere.

### What this enables
1. credible Hyper-V over SMB on Linux-backed storage
2. stable Windows interoperability for VM-disk workloads
3. low semantic debt relative to broader parity options

### Advantages
1. smallest engineering surface
2. strongest operational clarity
3. avoids fake compatibility
4. aligns with Program A

### Disadvantages
1. cannot claim NTFS parity
2. some Windows admin workflows will remain unsupported
3. certain metadata-heavy applications may not behave like Windows Server

### Verdict
This should be the default strategy unless there is strong product demand for broader compatibility.

## Comparison Table
| Option | Engineering Cost | Semantic Fidelity | Operational Burden | Best Use |
|---|---:|---:|---:|---|
| Extend `ntfs3` | Very High | High | High | true NTFS parity program |
| Metadata emulation layer | High | Medium | Very High | selective Windows metadata compatibility |
| Dedicated NTFS-aware backend | Very High | High | Very High | strategic Windows storage platform |
| Narrow claims on Linux FS | Low | Honest, limited | Low | Program A / realistic product |

## Recommended Decision Rules
1. If the goal is standalone Hyper-V over SMB, choose Option 4.
2. If the goal is selected Windows metadata compatibility without full NTFS parity, evaluate Option 2.
3. If the goal is real NTFS parity, choose between Option 1 and Option 3 only after executive approval for a multi-year program.
4. Do not mix options opportunistically without a written ownership model.

## Required Follow-Up Design Questions
1. Where is metadata stored?
2. How is rename/link/delete atomicity preserved?
3. How are backup/restore and fsck-like recovery handled?
4. What happens when sidecar metadata and filesystem state diverge?
5. How are crash-consistency guarantees specified?
6. Which Windows behaviors are intentionally out of scope even after architecture is chosen?

## Recommendation
For now:
1. default to Option 4 for Program A
2. evaluate Option 2 and Option 1 only if Program B is approved
3. reject Program B if no owner can defend crash consistency and supportability for the chosen NTFS strategy
