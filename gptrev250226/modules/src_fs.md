# Module Review: src/fs

- Files reviewed: 15
- Total lines reviewed: 14177

## File Coverage
- src/fs/ksmbd_app_instance.c (lines=294, range=1-294, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/fs/ksmbd_create_ctx.c (lines=240, range=1-240, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/fs/ksmbd_dfs.c (lines=219, range=1-219, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/fs/ksmbd_fsctl.c (lines=350, range=1-350, status=REVIEWED_WITH_FINDINGS, findings=KSMBD-F002,KSMBD-F010)
- src/fs/ksmbd_fsctl_extra.c (lines=425, range=1-425, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/fs/ksmbd_info.c (lines=612, range=1-612, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/fs/ksmbd_notify.c (lines=596, range=1-596, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/fs/ksmbd_quota.c (lines=393, range=1-393, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/fs/ksmbd_reparse.c (lines=745, range=1-745, status=REVIEWED_WITH_FINDINGS, findings=KSMBD-F009)
- src/fs/ksmbd_resilient.c (lines=146, range=1-146, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/fs/ksmbd_vss.c (lines=747, range=1-747, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/fs/oplock.c (lines=2256, range=1-2256, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/fs/smbacl.c (lines=1981, range=1-1981, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/fs/vfs.c (lines=3931, range=1-3931, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/fs/vfs_cache.c (lines=1242, range=1-1242, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)

## Findings In Module
- KSMBD-F002 [HIGH] FSCTL_VALIDATE_NEGOTIATE_INFO compares binary GUID with strncmp (src/fs/ksmbd_fsctl.c:210)
- KSMBD-F009 [MEDIUM] FSCTL_SET_REPARSE_POINT validates input but returns success without applying changes (src/fs/ksmbd_reparse.c:379-391)
- KSMBD-F010 [MEDIUM] FSCTL_CREATE_OR_GET_OBJECT_ID returns fixed all-zero object IDs (src/fs/ksmbd_fsctl.c:141-167)
