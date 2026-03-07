# Multi-Agent Methodology

## Parallel review lanes executed
- Lane A (`core/session/connection lifecycle`): `src/core/*`, `src/mgmt/*`
- Lane B (`protocol correctness and credit accounting`): `src/protocol/smb2/*`, `src/protocol/common/*`, `src/protocol/smb1/*`
- Lane C (`filesystem async/control paths`): `src/fs/*`
- Lane D (`transport and IPC surfaces`): `src/transport/*`

Each lane ran independent scans for:
- lock/wait/loop hazards,
- memory and overflow-sensitive operations,
- race/refcount/atomic lifecycle signals,
- explicit WARN/BUG and error-path behavior.

## “Line-by-line” strategy used
- Full-file automated pass across all `src/` files to build a coverage matrix and risk density (`05_FILE_COVERAGE_MATRIX.csv`).
- Manual line-by-line deep reads for top-risk files by concurrency and control-flow complexity:
  - `src/fs/ksmbd_notify.c`
  - `src/protocol/smb2/smb2_pdu_common.c`
  - `src/protocol/smb2/smb2misc.c`
  - `src/core/server.c`
  - `src/core/connection.c`
  - `src/transport/transport_ipc.c`
  - `src/protocol/smb2/smb2_lock.c`

## Commands/logs captured
- Raw grep/scans copied into:
  - `RAW_risk_hits.txt`
  - `RAW_mem_hits.txt`
  - `RAW_concurrency_hits.txt`

## Validation notes
- Host cannot build module currently due missing matching kernel headers.
- Findings here are based on source-consistency and concurrency semantics; runtime proof should be executed in VM matrix with lockdep/KCSAN/KASAN enabled kernels.
