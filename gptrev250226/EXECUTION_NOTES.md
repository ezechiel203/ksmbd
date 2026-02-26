# Execution Notes

## Commands run
- `cppcheck --enable=all --inconclusive --force ... src ksmbd-tools test tests`
- `shellcheck -S warning` on all discovered `*.sh` scripts
- `./run_tests.sh`
- targeted grep/pattern scans for TODO/FIXME, unsafe string APIs, allocation sites

## Raw outputs
- `raw/cppcheck.txt`
- `raw/cppcheck_filtered.tsv`
- `raw/shellcheck.txt`
- `raw/run_tests.txt`
- `raw/pattern_unsafe_strings.txt`
- `raw/pattern_allocations.txt`
- `raw/pattern_todo.txt`

## Important interpretation notes
- Many kernel-source `cppcheck` entries were preprocessor/include related (`missingInclude`, `syntaxError`, `unknownMacro`) and were filtered out for actionable review.
- Findings in `findings_catalog.tsv` were manually validated in source before being promoted to reportable issues.

