# Module Review: src/protocol

- Files reviewed: 20
- Total lines reviewed: 23662

## File Coverage
- src/protocol/common/netmisc.c (lines=606, range=1-606, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/protocol/common/smb_common.c (lines=888, range=1-888, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/protocol/smb1/smb1misc.c (lines=298, range=1-298, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/protocol/smb1/smb1ops.c (lines=96, range=1-96, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/protocol/smb1/smb1pdu.c (lines=8879, range=1-8879, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/protocol/smb2/smb2_create.c (lines=1987, range=1-1987, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/protocol/smb2/smb2_dir.c (lines=962, range=1-962, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/protocol/smb2/smb2_ioctl.c (lines=769, range=1-769, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/protocol/smb2/smb2_lock.c (lines=718, range=1-718, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/protocol/smb2/smb2_misc_cmds.c (lines=544, range=1-544, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/protocol/smb2/smb2_negotiate.c (lines=691, range=1-691, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/protocol/smb2/smb2_notify.c (lines=139, range=1-139, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/protocol/smb2/smb2_pdu_common.c (lines=1186, range=1-1186, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/protocol/smb2/smb2_query_set.c (lines=2352, range=1-2352, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/protocol/smb2/smb2_read_write.c (lines=720, range=1-720, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/protocol/smb2/smb2_session.c (lines=796, range=1-796, status=REVIEWED_WITH_FINDINGS, findings=KSMBD-F001)
- src/protocol/smb2/smb2_tree.c (lines=330, range=1-330, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/protocol/smb2/smb2fruit.c (lines=795, range=1-795, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/protocol/smb2/smb2misc.c (lines=491, range=1-491, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)
- src/protocol/smb2/smb2ops.c (lines=415, range=1-415, status=REVIEWED_NO_BLOCKER_FOUND, findings=-)

## Findings In Module
- KSMBD-F001 [HIGH] Binary GUID compared with strncmp instead of memcmp (src/protocol/smb2/smb2_session.c:569)
