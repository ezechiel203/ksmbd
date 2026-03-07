# Detailed Findings

## KSMBD-F001 (HIGH)
- Location: `src/protocol/smb2/smb2_session.c:569`
- Issue: `strncmp(conn->ClientGUID, sess->ClientGUID, SMB2_CLIENT_GUID_SIZE)` compares binary GUID bytes with string semantics.
- Risk: `strncmp` stops at `\0`; mismatched GUID tails can be ignored when early null bytes exist, weakening SMB3 multichannel session binding checks.
- Fix: Replace with `memcmp(conn->ClientGUID, sess->ClientGUID, SMB2_CLIENT_GUID_SIZE)`.

## KSMBD-F002 (HIGH)
- Location: `src/fs/ksmbd_fsctl.c:210`
- Issue: `FSCTL_VALIDATE_NEGOTIATE_INFO` compares `neg_req->Guid` to `conn->ClientGUID` using `strncmp`.
- Risk: negotiation validation can accept non-identical binary GUIDs when null bytes appear before byte 16.
- Fix: use `memcmp` for exact 16-byte comparison.

## KSMBD-F003 (HIGH)
- Location: `src/mgmt/share_config.c:179`, `src/mgmt/share_config.c:181`, `src/mgmt/share_config.c:232`, `src/mgmt/share_config.c:244`, `src/mgmt/share_config.c:102`
- Issue: `share->name = kstrdup(...)` is only validated inside the non-pipe branch; pipe shares can proceed with `share->name == NULL`.
- Risk: later lookup path does `strcmp(name, share->name)` and can dereference NULL.
- Fix: validate `share->name` immediately after allocation, before branching on `KSMBD_SHARE_FLAG_PIPE`.

## KSMBD-F004 (HIGH)
- Location: `src/mgmt/user_session.c:290`, `src/mgmt/user_session.c:326`, `src/mgmt/user_session.c:340-346`
- Issue: `to_destroy = krealloc(to_destroy, ...)` overwrites the only live pointer.
- Risk: if `krealloc` fails after entries already exist, `to_destroy` becomes NULL while `nr_destroy > 0`; teardown loop dereferences NULL.
- Fix: use temporary pointer (`tmp = krealloc(...)`), assign only on success; handle OOM without dropping old pointer.

## KSMBD-F005 (HIGH)
- Location: `run_tests.sh:406-411`
- Issue: test execution uses `if ! test_output=$(...)`; inside failure block, `$?` is captured after `!`, yielding `0`.
- Risk: failed suites can be logged as success and returned as success.
- Fix: capture command status directly without `!` inversion (or store status in a variable immediately after command execution).

## KSMBD-F006 (MEDIUM)
- Location: `run_tests.sh:346`, `run_tests.sh:349`, `run_tests.sh:352`, `run_tests.sh:355`
- Issue: in native mode, integration/security/performance paths run `--help`/`--list` commands.
- Risk: these suites do not validate runtime behavior; regressions can pass CI.
- Fix: execute real suite commands (not help/list placeholders) and assert pass/fail criteria.

## KSMBD-F007 (MEDIUM)
- Location: `build_ksmbd.sh:6`, `build_ksmbd.sh:11-16`, `build_ksmbd.sh:24-76`
- Issue: shebang is not first line; script advertises `/bin/sh` but uses bash-only constructs (`function`, `local`, `==`) and command substitutions that redirect output away.
- Risk: portability/correctness failures during build/install automation.
- Fix: move shebang to line 1; choose `#!/bin/bash` or strictly POSIX syntax; remove malformed `ok=$(echo ... >> file)` patterns.

## KSMBD-F008 (MEDIUM)
- Location: `build_arm64.sh:215`, `build_arm64.sh:225`
- Issue: make arguments are concatenated into a single string containing embedded quotes.
- Risk: debug flags may be split or passed with literal quotes; build behavior becomes shell-dependent.
- Fix: build command using bash arrays (`make_args=(...)`) and invoke `make "${make_args[@]}" modules`.

## KSMBD-F009 (MEDIUM)
- Location: `src/fs/ksmbd_reparse.c:379-391`
- Issue: `FSCTL_SET_REPARSE_POINT` currently validates input and returns success but does not perform replacement/write.
- Risk: protocol-visible false success and state divergence.
- Fix: either implement actual atomic replacement path, or return explicit unsupported status until implemented.

## KSMBD-F010 (MEDIUM)
- Location: `src/fs/ksmbd_fsctl.c:141-167`
- Issue: `FSCTL_CREATE_OR_GET_OBJECT_ID` returns an all-zero object ID as a placeholder.
- Risk: non-compliant behavior and potential object-ID collisions.
- Fix: generate stable object IDs per file semantics, or reject as unsupported.

## KSMBD-F011 (LOW)
- Location: `ksmbd-tools/mountd/ipc.c:32-35`
- Issue: `msg_sz = sz + sizeof(...) + 1` has no overflow-safe addition.
- Risk: hardening gap in message allocator.
- Fix: use checked addition helper before bounds check/allocation.

## KSMBD-F012 (LOW)
- Location: `Makefile:173-184`
- Issue: DKMS targets use unsanitized `PKGVER` in privileged path operations.
- Risk: operator-supplied edge values can target unexpected paths.
- Fix: validate `PKGVER` against strict safe charset before filesystem commands.

