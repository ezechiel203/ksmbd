# REVIEW_GPT_050326

This folder contains the March 5, 2026 deep review focused on ksmbd kernel safety, security, and stability.

## Start here
1. `00_EXEC_SUMMARY.md`
2. `02_FINDINGS_SECURITY_STABILITY.md`
3. `03_REFACTOR_ROADMAP.md`
4. `06_AGENT_WORK_PACKETS.md`

## Data files
- `05_FILE_COVERAGE_MATRIX.csv`
- `09_FINDINGS_INDEX.csv`
- `RAW_risk_hits.txt`
- `RAW_mem_hits.txt`
- `RAW_concurrency_hits.txt`

## Line-level audit corpus
- `LINE_AUDIT/ALL_LINES_TAGGED.csv` (88,096 lines)
- `LINE_AUDIT/TOP_WAIT_LOCK_RISK.csv`
- `LINE_AUDIT/HIGH_RISK_EXTRACTS/` (12 deep extracts)

## Detailed per-file review corpus
- `DETAILED_REVIEW/` (line-by-line review files for all `src/*.c` and `src/*.h`)

## Applied hardening patches
- `11_PATCHES_APPLIED_20260305.md`
- `12_REFINED_ANALYSIS_20260305.md`
