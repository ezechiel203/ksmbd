# Module Review: src/mgmt

- Files reviewed: 10
- Total lines reviewed: 1668

## File Coverage
- src/mgmt/ksmbd_ida.c (lines=56, range=1-56, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/mgmt/ksmbd_ida.h (lines=40, range=1-40, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/mgmt/share_config.c (lines=293, range=1-293, status=REVIEWED_WITH_FINDINGS, findings=KSMBD-F003)
- src/mgmt/share_config.h (lines=81, range=1-81, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/mgmt/tree_connect.c (lines=180, range=1-180, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/mgmt/tree_connect.h (lines=65, range=1-65, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/mgmt/user_config.c (lines=111, range=1-111, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/mgmt/user_config.h (lines=70, range=1-70, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/mgmt/user_session.c (lines=643, range=1-643, status=REVIEWED_WITH_FINDINGS, findings=KSMBD-F004)
- src/mgmt/user_session.h (lines=129, range=1-129, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)

## Findings In Module
- KSMBD-F003 [HIGH] Pipe-share path skips share->name allocation failure check (src/mgmt/share_config.c:179,181,232,244,102)
- KSMBD-F004 [HIGH] Direct assignment of krealloc result can lose prior pointer on OOM (src/mgmt/user_session.c:290,326,340-346)
