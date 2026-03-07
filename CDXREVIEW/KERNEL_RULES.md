# Kernel Rule / Style Compliance (Re-Validation)

## Summary
- `checkpatch` (core filtered set) processed `110` files and `62,365` lines.
- Totals: `115` errors, `1,215` warnings.
- Raw evidence: `raw/ci_checkpatch_core.log`.

## Most Frequent Warning Classes (core)
- `LINUX_VERSION_CODE`: 455
- `CONSTANT_COMPARISON`: 452
- `LEADING_SPACE`: 218
- `AVOID_EXTERNS`: 17
- `EMBEDDED_FILENAME`: 13
- `SUSPECT_CODE_INDENT`: 13

## Hotspot Files (error+warning count)
- `vfs.c`: 385 (0 errors, 385 warnings)
- `memory_usage_validator.c`: 263 (48 errors, 215 warnings)
- `smbacl.c`: 102 (0 errors, 102 warnings)
- `smb2_create.c`: 75 (0 errors, 75 warnings)
- `smb2_query_set.c`: 65 (0 errors, 65 warnings)
- `smb2_lock.c`: 41 (2 errors, 39 warnings)

## Notes
- Style totals remain materially high even though functional blockers were addressed.
- Version-compat branching still dominates warnings and is the best candidate for structural cleanup.
