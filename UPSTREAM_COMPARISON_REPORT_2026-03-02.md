# KSMBD / KSMBD-TOOLS Upstream Comparison Report

Date: 2026-03-02

## 1) Scope and Baselines

This report compares your current working branches against official upstream GitHub repositories.

- ksmbd local branch: `phase1-security-hardening` at `0bfefe47`
- ksmbd upstream baseline: `upstream/master` at `1c26a5f0`
- ksmbd-tools local branch: `phase1-security-hardening` at `dc972bd`
- ksmbd-tools upstream baseline: `upstream/master` at `f6c2b20`

Official upstream repos:

- `https://github.com/cifsd-team/ksmbd`
- `https://github.com/cifsd-team/ksmbd-tools`

## 2) Methodology

I ran parallel analysis on both repos:

- commit-range analysis (`upstream/master..phase1-security-hardening`)
- code-only diff stats (excluding most review artifacts)
- directory-level and file-level churn analysis
- targeted reads of critical implementation files for technical interpretation

Important caveat:

- The `ksmbd` tree includes a large structural re-layout to `src/...` plus extensive docs/review artifacts. Raw commit/file counts overstate net-new protocol behavior because some content is reorganized, duplicated, or mirrored from prior flat files.

## 3) High-Level Delta Size

### ksmbd (full range)

- Commits ahead of upstream: `753`
- Files changed: `444`
- Net delta: `170,886 insertions / 11,827 deletions`

### ksmbd (code-focused paths)

- Files changed: `167`
- Net delta: `92,996 insertions / 46 deletions`
- Largest changed code areas by added LOC:
  - `src/protocol`: `29,046`
  - `src/fs`: `23,636`
  - `src/include`: `13,211`
  - `src/transport`: `8,182`
  - `src/core`: `8,152`

### ksmbd-tools (full range)

- Commits ahead of upstream: `310`
- Files changed: `68`
- Net delta: `7,443 insertions / 657 deletions`

### ksmbd-tools (code-focused paths)

- Files changed: `64`
- Net delta: `7,184 insertions / 618 deletions`
- Largest changed code/docs surfaces:
  - `ksmbd.conf.example`: `+1198/-50`
  - `ksmbdctl.8.in`: `+1133/-0`
  - `tools/ksmbdctl.c`: `+990/-0`
  - `tests/test_config_parser.c`: `+751/-0`
  - `include/linux/ksmbd_server.h`: `+249/-106`

## 4) Broad ksmbd Changes vs Upstream

## 4.1 Source Architecture and Build System

- Major tree reorganization from mostly flat/legacy layout into structured `src/core`, `src/fs`, `src/protocol`, `src/transport`, `src/mgmt`, `src/encoding`, `src/include`.
- Makefile rewritten around structured object lists and feature toggles.
- External module build flow expanded with deploy/install/dkms and per-feature flags.
- Kconfig extended with stronger security guidance and additional feature controls.

Representative files:

- `Makefile`
- `Kconfig`
- `src/include/...`

## 4.2 Protocol Surface Expansion

- SMB1 implementation appears significantly expanded/refactored (`smb1pdu`, `smb1ops`, `smb1misc`, protocol headers).
- SMB2 command handling split into more focused compilation units and expanded in create/query/ioctl/notify/session/tree/read-write paths.
- FSCTL coverage heavily expanded, including ODX/dup extents/integrity/query file regions/branchcache/reserved control paths.
- Witness protocol scaffolding and handlers added through mgmt + transport IPC layers.
- QUIC transport introduced as kernel-side implementation path (currently in-tree code, plus userspace handshake bridge assumptions).
- Compression paths and SMB3-related multi-channel/session hardening appear expanded.

Representative files:

- `src/protocol/smb1/smb1pdu.c`
- `src/protocol/smb2/smb2_create.c`
- `src/protocol/smb2/smb2_query_set.c`
- `src/fs/ksmbd_fsctl.c`
- `src/transport/transport_quic.c`
- `src/transport/transport_ipc.c`
- `src/mgmt/ksmbd_witness.c`

## 4.3 Security and Robustness Focus

Commit subjects and touched code strongly indicate emphasis on:

- protocol conformance hardening
- bounds and overflow checks
- session/credit/encryption/signing correctness
- lock/lifetime safety in notify/oplock/session paths
- SMB1 risk containment and compatibility adjustments

Also present:

- embedded MD4-related support in module-side code paths
- additional debug gating and instrumentation in contested paths

## 4.4 Test/CI/Validation Expansion

- Added/expanded KUnit, fuzz, integration, and smbtorture runners.
- Added benchmarking scripts and CI helper scripts.
- VM orchestration expanded for multi-VM regression workflows.

Representative files:

- `tests/run_smbtorture.sh`
- `tests/run_integration.sh`
- `tests/run_xfstests.sh`
- `test/fuzz/*`
- `.github/scripts/ci-build-module.sh`
- `vm/run-regression-matrix.sh`

## 4.5 Documentation/Review Corpus Growth

- Very large volume of plans, reviews, compliance notes, and generated analysis artifacts included in-tree.
- These files are useful for internal tracking but significantly increase review and upstreaming noise.

## 5) Technical ksmbd Delta Highlights

## 5.1 Build and Feature Matrix

- `Makefile` now wires feature flags for:
  - `CONFIG_SMB_INSECURE_SERVER`
  - `CONFIG_KSMBD_FRUIT`
  - `CONFIG_SMB_SERVER_QUIC`
  - `CONFIG_SMB_SERVER_SMBDIRECT`
- External build defaults are feature-on for multiple options, with command-line disable support.

Technical effect:

- Faster feature toggling during VM test cycles.
- Increased risk of accidental feature skew if userspace and kernel do not match expected ABI/features.

## 5.2 QUIC Transport Integration

- `src/transport/transport_quic.c` introduces kernel-side QUIC framing/crypto state machinery and handshake delegation concepts.
- Design comments indicate RFC 9000/9001-oriented handling and netlink-based coordination.

Technical effect:

- Enables direct experimentation with SMB-over-QUIC in kernel path.
- Significantly increases complexity in transport state machine, key lifecycle, and IPC coordination.

## 5.3 FSCTL and File-Service Behavior

- `src/fs/ksmbd_fsctl.c` and related files expanded with many FSCTL handlers.
- Includes ODX/duplicate extents/integrity/query regions, plus misc feature parity behavior.

Technical effect:

- Better client compatibility and protocol feature exposure.
- Larger attack surface and more stateful paths requiring rigorous validation tests.

## 5.4 SMB2/SMB3 Path Hardening

- Substantial edits in create/query/read-write/session/negotiate/dir/compound areas.
- Commit trail indicates work on durable handles, leases/oplocks, multichannel constraints, compression, and credits.

Technical effect:

- Clear protocol-depth investment.
- Regression risk remains concentrated in compound/session/credit interplay under stress.

## 5.5 Witness and IPC Extensions

- Witness request/response/event structures and handlers added across module and management layers.
- Transport IPC expanded around event handling and response validation.

Technical effect:

- Adds HA/failover-related protocol capabilities.
- Tight coupling to userspace ABI; any mismatch can terminate mountd worker or degrade login paths.

## 6) Broad ksmbd-tools Changes vs Upstream

## 6.1 Unified CLI Consolidation

- Major UX/control shift to `ksmbdctl` as the primary entrypoint.
- User/share/debug/config/start/stop/reload/status/features/version management consolidated.

Representative file:

- `tools/ksmbdctl.c`

## 6.2 Operational Control Improvements

- Control layer includes richer server lifecycle operations and status/features output.
- Better mountd notification/reload logic and service interaction patterns.

Representative file:

- `control/control.c`

## 6.3 Config Surface Expansion

- `ksmbd.conf.example` and parser paths expanded significantly.
- Fruit options, ACL/host handling, and other global/share settings enhanced.

Representative files:

- `ksmbd.conf.example`
- `tools/config_parser.c`
- `tools/management/share.c`

## 6.4 IPC/Netlink Handling Changes

- Header synchronization effort (`include/linux/ksmbd_server.h`) and IPC handling changes in mountd.
- Additional validations and error handling added in IPC request processing.

Representative files:

- `include/linux/ksmbd_server.h`
- `mountd/ipc.c`
- `mountd/worker.c`

## 6.5 Tests and Packaging

- New unit/integration/compat tests added in `tests/`.
- Build/install scripts and meson/autotools integration broadened.

Representative files:

- `tests/test_ipc_compat.sh`
- `tests/test_ipc_request_validation.c`
- `scripts/install_ksmbd_tools_optusr.sh`

## 7) Technical ksmbd-tools Delta Highlights

## 7.1 ksmbdctl Command Surface

`ksmbdctl` now includes:

- lifecycle: `start`, `stop`, `reload`, `status`, `features`, `version`
- user operations: `add/set/update/delete/list`
- share operations: `add/set/update/delete/list/show`
- debug operations: `set/show/off`
- config operations: `show/validate`

Technical effect:

- Better operator ergonomics and scriptability.
- Requires strict compatibility with mountd internals and lock-file semantics.

## 7.2 IPC Robustness and Compatibility Sensitivity

- IPC handlers include tighter validation and explicit handling for unsupported events.
- Your current branch includes additional fallback behavior for out-of-range netlink command parsing.

Technical effect:

- Better survivability under ABI drift.
- Still sensitive to kernel/userspace mismatch and wrong module load source.

## 7.3 Share/User Management Refinement

- More robust option parsing and management-path behavior.
- Supplementary groups and ACL/host checks appear improved.

Technical effect:

- Better correctness and administration workflows.
- Needs ongoing parity checks with kernel-side expectations.

## 8) Observed Divergence Risks vs Upstream

- Divergence size is very high, especially in `ksmbd`.
- Large in-tree review artifacts obscure core code review and make upstream rebasing harder.
- Kernel/userspace ABI coupling (netlink structs/events/policies) remains the top operational risk.
- Mixed loading paths (distro in-tree module vs out-of-tree module) can invalidate runtime conclusions if not enforced.

## 9) Practical Upstreaming/Consolidation Strategy

- Split into thematic series, each with isolated test proof:
  - source tree refactor/build changes
  - protocol parity changes (SMB1/SMB2/SMB3) by subsystem
  - FSCTL/ODX/RSVD series
  - QUIC/witness series
  - ksmbd-tools CLI/config/parser series
- Remove generated review artifacts from core branches or move to separate docs branch.
- Enforce version-coupled CI matrix:
  - exact `ksmbd.ko` srcversion + `ksmbd-tools` version pairing
  - explicit module load path checks (`modinfo -n ksmbd`, `/sys/module/ksmbd/srcversion`)
- Keep a protocol regression matrix as gate criteria (smbtorture subsets + stress + negative tests).

## 10) Bottom Line

Relative to official upstream, your fork is not a small patchset. It is a broad platform branch with:

- major source-layout and build-system changes,
- substantial protocol-surface expansion (SMB1/SMB2/SMB3, FSCTL, witness, QUIC),
- significant ksmbd-tools UX/IPC/config evolution,
- and expanded VM/test automation.

This branch materially increases capability and experimentation speed, but it also increases integration complexity and long-term rebase/upstream maintenance cost.
