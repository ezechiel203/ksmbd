# ksmbd Code Coverage

This directory contains infrastructure for measuring how much production
code the KUnit tests exercise, using the kernel's built-in gcov support
and the lcov/genhtml toolchain.

---

## Prerequisites

Install the following tools on your development machine:

```bash
# Debian/Ubuntu
sudo apt-get install lcov gcc

# Arch Linux
sudo pacman -S lcov gcc

# Fedora/RHEL
sudo dnf install lcov gcc
```

You also need a **full Linux kernel source tree** (not just headers) to
build with gcov instrumentation and run tests via kunit.py.

---

## Quick Start

### Option A: Full pipeline (recommended)

```bash
# From the ksmbd repository root:
LINUX_SRC=/path/to/linux make -f test/coverage/Makefile coverage-all
```

This will:
1. Copy ksmbd into the kernel source tree
2. Build with gcov instrumentation via kunit.py
3. Run all KUnit tests
4. Collect gcov data and generate an HTML coverage report

The report will be at `test/coverage/output/coverage_html/index.html`.

### Option B: Step by step

```bash
# 1. Build ksmbd with gcov
LINUX_SRC=/path/to/linux make -f test/coverage/Makefile coverage-build

# 2. Run KUnit tests
LINUX_SRC=/path/to/linux make -f test/coverage/Makefile coverage-run

# 3. Generate the report
LINUX_SRC=/path/to/linux make -f test/coverage/Makefile coverage-report
```

### Option C: Direct script usage

If you have already run `kunit.py run` with gcov enabled, you can skip
the build and just generate the report:

```bash
./test/coverage/collect_coverage.sh --linux-src /path/to/linux
```

### Option D: Real hardware

On a running system with ksmbd built with `CONFIG_GCOV_KERNEL=y` and
`GCOV_PROFILE := y` in the ksmbd Makefile:

```bash
# Must be root (debugfs access)
sudo mount -t debugfs none /sys/kernel/debug 2>/dev/null

# Load ksmbd and run tests...
sudo modprobe ksmbd

# Collect coverage
sudo ./test/coverage/collect_coverage.sh --output-dir /tmp/ksmbd_cov
```

---

## How It Works

### Architecture

The coverage pipeline has three stages:

```
Build with gcov          Run tests           Collect + report
+------------------+    +--------------+    +------------------+
| CONFIG_GCOV=y    |    | kunit.py run |    | lcov --capture   |
| GCOV_PROFILE := y| -> | (UML kernel) | -> | lcov --extract   |
| ksmbd sources    |    | KUnit suites |    | genhtml          |
+------------------+    +--------------+    +------------------+
                                             |
                                             v
                                        HTML report
                                        (index.html)
```

### Kernel gcov

The Linux kernel supports gcov natively via `CONFIG_GCOV_KERNEL=y`.
When enabled, the compiler instruments every function with counters
that record which lines and branches are executed. The counters are
exposed via:

- **UML builds**: `.gcda` and `.gcno` files in the build directory
- **Real hardware**: `/sys/kernel/debug/gcov/` pseudo-filesystem

### Per-module instrumentation

Rather than instrumenting the entire kernel (`CONFIG_GCOV_PROFILE_ALL=y`),
we use per-directory profiling by adding `GCOV_PROFILE := y` to the
ksmbd Makefile. This keeps build times reasonable and focuses coverage
data on ksmbd code.

### lcov/genhtml

- `lcov --capture` reads `.gcda` files and produces a `.info` tracefile
- `lcov --extract` filters to only ksmbd source files
- `lcov --remove` strips out test code (we want production code coverage)
- `genhtml` turns the `.info` file into a browsable HTML report

---

## Interpreting the Report

### HTML Report Layout

The generated HTML report (`coverage_html/index.html`) shows:

- **Top-level view**: Overall line, function, and branch coverage percentages
- **Directory view**: Coverage broken down by directory (root, mgmt/)
- **File view**: Per-file coverage with source code annotation
- **Line-level detail**: Green = covered, red = not covered, no color = non-executable

### Coverage Metrics

| Metric     | Description |
|------------|-------------|
| **Lines**     | Percentage of executable source lines that were reached |
| **Functions** | Percentage of functions that were called at least once |
| **Branches**  | Percentage of branch conditions evaluated both ways |

### What to look for

- **Red files**: Source files with 0% coverage likely have no corresponding
  KUnit tests. Consider adding test coverage for critical code paths.
- **Red lines in covered files**: These are branches or error paths that
  existing tests do not exercise. Add test cases targeting those paths.
- **High coverage files**: Core utility functions (misc.c, unicode.c) tend
  to have the highest coverage since they are easiest to unit test.

---

## Adding Coverage for a New Source File

If you add a new `.c` file to ksmbd and want it included in coverage:

1. The file will automatically be instrumented if it is listed in the
   ksmbd Makefile's `ksmbd-y` variable (standard kbuild).

2. No changes to the coverage infrastructure are needed -- lcov will
   automatically pick up any `.gcda` files produced under `*/ksmbd/`.

3. To verify coverage, write KUnit tests for the new file's functions
   and run the coverage pipeline.

---

## Coverage Thresholds

The `collect_coverage.sh` script supports threshold enforcement:

```bash
# Fail if line coverage drops below 30%
./test/coverage/collect_coverage.sh \
    --linux-src /path/to/linux \
    --min-line-coverage 30

# Check both line and function coverage
./test/coverage/collect_coverage.sh \
    --linux-src /path/to/linux \
    --min-line-coverage 30 \
    --min-func-coverage 20

# Enable branch coverage tracking (slower, more detailed)
./test/coverage/collect_coverage.sh \
    --linux-src /path/to/linux \
    --branch-coverage \
    --min-branch-coverage 15
```

Exit code `2` indicates a threshold was not met.

---

## Current Coverage Baseline Expectations

Since KUnit tests run in a limited environment (no real network, no real
VFS operations, no real authentication), coverage expectations vary by
subsystem:

| Source File Area        | Expected Coverage | Notes |
|-------------------------|-------------------|-------|
| misc.c, unicode.c      | 50-80%           | Pure logic, easy to test |
| auth.c, crypto_ctx.c   | 20-50%           | Partial (crypto helpers testable) |
| smb2pdu.c, smb2misc.c  | 10-30%           | PDU parsing testable, handlers less so |
| vfs.c, vfs_cache.c     | 10-20%           | Heavily depends on real VFS |
| connection.c, server.c | 5-15%            | Runtime-dependent |
| transport_tcp.c         | 0-5%             | Requires real sockets |
| transport_rdma.c        | 0%               | Requires InfiniBand hardware |
| smb1pdu.c, smb1ops.c   | 10-30%           | Legacy, partial test coverage |
| mgmt/*.c               | 20-40%           | Config/session management testable |

These are approximate baselines for the initial KUnit test suite.
Coverage should improve as more tests are added.

---

## Integration with CI

### GitHub Actions

Add a coverage step to your CI workflow:

```yaml
- name: Run KUnit with coverage
  run: |
    LINUX_SRC=${{ github.workspace }}/linux \
    make -f test/coverage/Makefile coverage-all

- name: Check coverage thresholds
  run: |
    ./test/coverage/collect_coverage.sh \
        --linux-src ${{ github.workspace }}/linux \
        --min-line-coverage 25 \
        --min-func-coverage 15

- name: Upload coverage report
  uses: actions/upload-artifact@v4
  with:
    name: ksmbd-coverage-report
    path: test/coverage/output/coverage_html/
```

### Local pre-push hook

```bash
#!/bin/bash
# .git/hooks/pre-push
LINUX_SRC=/path/to/linux make -f test/coverage/Makefile coverage-all
./test/coverage/collect_coverage.sh \
    --linux-src /path/to/linux \
    --min-line-coverage 25
```

---

## Cleaning Up

```bash
# Remove all generated coverage data
make -f test/coverage/Makefile coverage-clean

# Or manually
rm -rf test/coverage/output/
```

---

## Troubleshooting

### "No coverage data captured"

- Verify the kernel was built with `CONFIG_GCOV_KERNEL=y`
- Check that `GCOV_PROFILE := y` is in the ksmbd Makefile
- Ensure KUnit tests actually ran (check kunit_run.log)

### "lcov: ERROR: no valid records found"

- The gcov version may not match the compiler used to build the kernel.
  Ensure `gcov` in PATH matches the `gcc` that built the kernel.

### Large build times

- `CONFIG_GCOV_PROFILE_ALL=y` instruments the entire kernel. The coverage
  Makefile uses per-directory `GCOV_PROFILE := y` instead, which is much
  faster.

### UML build failures

- UML does not support some kernel features. Check the kunit.kunitconfig
  for incompatible options.
- Run `kunit.py config` first to verify the config merges cleanly.

### Empty report after filtering

- If lcov `--extract` produces no output, the source file paths in the
  `.info` file may not match the filter patterns. Use `--keep-intermediates`
  and inspect the raw `.info` file to see the actual paths.
