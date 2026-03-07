# ksmbd-tools Review

Reviewed areas:
- `mountd/`
- `tools/management/`
- `tools/`
- `control/`
- `tests/`

## Findings

### 1. Medium: DCE/RPC NDR helpers rely on unaligned typed accesses

References:
- `mountd/rpc.c:275`
- `mountd/rpc.c:282`
- `mountd/rpc.c:294`
- `mountd/rpc.c:304`
- `mountd/smbacl.c:47`
- `mountd/rpc.c:852`
- `mountd/rpc.c:886`

Why this matters:
- `NDR_WRITE_INT()` writes with `*(type *)PAYLOAD_HEAD(dce) = ...`.
- `NDR_READ_INT()` reads with `ret = le(*(type *)PAYLOAD_HEAD(dce))` / `be(...)`.
- Those operations assume the payload pointer is naturally aligned for `__u16`, `__u32`, and `__u64`.
- The build already emits warnings for packed-member destinations in `mountd/rpc.c` and `mountd/smbacl.c`, which is a concrete symptom of the same portability problem.

Risk:
- On strict-alignment architectures, this can fault or misbehave when parsing or serializing RPC/NDR payloads.
- The project explicitly targets non-x86 builds elsewhere, so relying on x86-style tolerant unaligned access is not defensible.

Recommendation:
- Replace typed pointer dereferences with `memcpy()` to/from local aligned temporaries before endian conversion.
- Avoid writing directly into packed struct members through typed pointers; decode into local variables and copy out.
- After fixing, rebuild with `-Werror=address-of-packed-member` or an equivalent CI gate for this area.

### 2. Medium: Host ACL CIDR parsing accepts malformed prefixes via `atoi()`

References:
- `tools/management/share.c:941`
- `tools/management/share.c:966`
- `tools/management/share.c:984`

Why this matters:
- `match_host_cidr()` parses the prefix with `atoi(slash + 1)`.
- `atoi()` accepts leading numeric fragments and ignores trailing garbage.
- As a result, strings such as `192.168.1.0/24junk` or `10.0.0.0/8anything` are silently treated as valid CIDR rules instead of configuration errors.

Risk:
- Admin mistakes in `hosts allow` / `hosts deny` become silent policy changes rather than explicit failures.
- In access-control code, silently broadening or narrowing a network match is the wrong failure mode.

Recommendation:
- Parse with `strtol()` or `g_ascii_strtoll()` and require full-string consumption.
- Reject negative values, values above the address width, and any trailing characters after the prefix.
- Add regression tests for malformed suffixes and overflow cases.

## Additional notes

- `tools/config_parser.c:1061` has misleading indentation in `verify_mountd_pid()`. It does not change current behavior because the early return is real, but it is easy to misread and should be cleaned up.
- `verify_mountd_pid()` only checks `/proc/<pid>/comm` for `ksmbd.mountd` or `ksmbdctl`. That is weak process identity validation for a lock file and can produce false live-lock detection after PID reuse or when another `ksmbdctl` instance is running.
- Test status from this review:
  - `build2`: 27/27 passed.
  - `build`: `ipc-handlers` hung repeatedly, while the rest passed. I treated that as a build-dir/environment inconsistency rather than a code finding because `build2` passed the same suite.
