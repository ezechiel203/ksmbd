# Sweep Results — 2026-03-07 (commit a7130c5d + fsnotify/wait fixes)

## Totals
PASS=369 FAIL=98 SKIP=33 ERROR=3
Total tests: 500

## Per-Suite Results
| Suite | PASS | FAIL | SKIP | ERR |
|-------|------|------|------|-----|
| compound | 20 | 0 | 0 | 0 |
| compound_async | 7 | 3 | 0 | 0 |
| compound_find | 3 | 0 | 0 | 0 |
| connect | 1 | 0 | 0 | 0 |
| create | 15 | 2 | 1 | 0 |
| credits | 5 | 5 | 0 | 0 |
| delete-on-close-perms | 6 | 3 | 0 | 0 |
| dir | 9 | 0 | 0 | 0 |
| dirlease | 18 | 0 | 0 | 0 |
| dosmode | 0 | 1 | 0 | 0 |
| durable-open | 23 | 2 | 1 | 0 |
| durable-v2-open | 30 | 3 | 0 | 0 |
| getinfo | 8 | 0 | 0 | 0 |
| ioctl | 51 | 9 | 15 | 0 |
| lease | 34 | 3 | 1 | 1 |
| lock | 22 | 0 | 4 | 0 |
| maxfid | 1 | 0 | 0 | 0 |
| maximum_allowed | 1 | 1 | 0 | 0 |
| mkdir | 0 | 1 | 0 | 0 |
| mux | 0 | 0 | 0 | 0 |
| notify | 18 | 5 | 0 | 0 |
| openattr | 0 | 1 | 0 | 0 |
| oplock | 38 | 4 | 0 | 0 |
| read | 4 | 0 | 1 | 0 |
| rename | 13 | 0 | 0 | 0 |
| replay | 10 | 8 | 0 | 1 |
| rw | 4 | 0 | 0 | 0 |
| secleak | 0 | 1 | 0 | 0 |
| session | 16 | 42 | 10 | 1 |
| setinfo | 1 | 0 | 0 | 0 |
| streams | 11 | 3 | 0 | 0 |
| zero-data-ioctl | 0 | 1 | 0 | 0 |

## Unfixable Failures (~64)
- session.bind_negative_* (38) — requires multichannel
- session.reauth5 (1) — Samba test bug
- session.anon-encryption1/2 (2) — anonymous+encryption
- replay.dhv2-pending* (8) — not implemented
- credits.multichannel_* (2) — requires multichannel
- secleak/dosmode/zero-data-ioctl (3) — test env config
- ioctl.bug14769/bug14788.* (3) — Samba-specific FSCTLs
- ioctl.sparse_punch/hole_dealloc/lock (3) — ext4 limitations
- ioctl.dup_extents_len_beyond_*/sparse_src (3) — clone range limitations

## Potentially Fixable (~34)
- compound_async: write_write, read_read, getinfo_middle (3)
- create: gentest, mkdir-visible (2)
- credits: ipc_max_data_zero, 1conn/2conn_ipc_max_async_credits (3)
- delete-on-close-perms: OVERWRITE_IF, CREATE_IF, READONLY (3)
- durable-open: delete_on_close2, alloc-size (2)
- durable-v2-open: nonstat-and-lease, keep-disconnected-rh-* (3)
- lease: breaking3, v2_breaking3, v2_complex1 (3)
- maximum_allowed (1)
- mkdir (1)
- notify: valid-req, mask-change, invalid-reauth, tree, rec (5)
- openattr (1)
- oplock: batch3, batch7, batch22b, statopen1 (4)
- streams: names, names2, names3 (3)
