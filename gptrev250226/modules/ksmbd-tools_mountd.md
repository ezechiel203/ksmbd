# Module Review: ksmbd-tools/mountd

- Files reviewed: 11
- Total lines reviewed: 5687

## File Coverage
- ksmbd-tools/mountd/Makefile.am (lines=22, range=1-22, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- ksmbd-tools/mountd/ipc.c (lines=529, range=1-529, status=REVIEWED_WITH_FINDINGS, findings=KSMBD-F011)
- ksmbd-tools/mountd/meson.build (lines=35, range=1-35, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- ksmbd-tools/mountd/mountd.c (lines=472, range=1-472, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- ksmbd-tools/mountd/rpc.c (lines=1380, range=1-1380, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- ksmbd-tools/mountd/rpc_lsarpc.c (lines=739, range=1-739, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- ksmbd-tools/mountd/rpc_samr.c (lines=1055, range=1-1055, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- ksmbd-tools/mountd/rpc_srvsvc.c (lines=477, range=1-477, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- ksmbd-tools/mountd/rpc_wkssvc.c (lines=240, range=1-240, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- ksmbd-tools/mountd/smbacl.c (lines=345, range=1-345, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- ksmbd-tools/mountd/worker.c (lines=393, range=1-393, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)

## Findings In Module
- KSMBD-F011 [LOW] ipc_msg_alloc lacks overflow-safe size addition (ksmbd-tools/mountd/ipc.c:32-35)
