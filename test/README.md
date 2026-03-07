# ksmbd Test Infrastructure

This document describes how to build and run every type of test in the ksmbd
project: KUnit unit tests, fuzz harnesses (kernel and userspace), and
integration tests via the ksmbd-torture framework.

---

## Quick Start

```bash
# 1. Verify all test/fuzz files are registered in Makefiles (CI gate):
./test/check_test_registration.sh

# 2. Build KUnit tests (requires kernel source tree):
make -C /path/to/linux M=$(pwd) CONFIG_SMB_SERVER=m CONFIG_KSMBD_KUNIT_TEST=m modules

# 3. Build userspace fuzz targets (requires clang with libFuzzer):
cd test/fuzz/userspace && make

# 4. Run the orchestrator script:
./test/run_all_tests.sh --all
```

---

## KUnit Tests (Unit Tests)

KUnit is the Linux kernel's built-in unit test framework. ksmbd ships 144+
KUnit test files in `test/ksmbd_test_*.c`, registered via `test/Makefile`.

### Building with an In-tree Kernel

Copy ksmbd into a kernel source tree and enable KUnit:

```bash
cp -ar . /path/to/linux/fs/ksmbd/

# In the kernel tree:
make menuconfig
# Enable: Kernel hacking -> KUnit -> KUnit tests for ksmbd
# Or append to .config:
echo 'CONFIG_KUNIT=y'               >> .config
echo 'CONFIG_SMB_SERVER=y'          >> .config
echo 'CONFIG_SMB_INSECURE_SERVER=y' >> .config
echo 'CONFIG_KSMBD_KUNIT_TEST=y'    >> .config

make -j$(nproc)
```

### Running with kunit.py (Recommended for CI)

The `kunit.py` tool builds a UML (User Mode Linux) kernel and runs tests
without requiring root or real hardware:

```bash
cd /path/to/linux
./tools/testing/kunit/kunit.py run \
    --kunitconfig=fs/ksmbd/test/kunit.kunitconfig \
    --arch=um
```

The `test/kunit.kunitconfig` file enables all necessary config symbols
(crypto, NLS, networking) for a self-contained UML build.

### Running on Real Hardware

If ksmbd is built as a module with `CONFIG_KSMBD_KUNIT_TEST=m`:

```bash
sudo modprobe ksmbd
# KUnit test modules are auto-loaded; results appear in dmesg:
dmesg | grep -E 'kunit|KUNIT'
```

### Expected Output

KUnit prints results in TAP (Test Anything Protocol) format:

```
    # Subtest: ksmbd_misc_test
    1..5
    ok 1 - test_match_pattern_exact
    ok 2 - test_match_pattern_star
    ok 3 - test_match_pattern_question
    ok 4 - test_match_pattern_combined
    ok 5 - test_match_pattern_empty
ok 1 - ksmbd_misc_test
```

### Adding a New KUnit Test File

1. Create `test/ksmbd_test_<name>.c` following the existing pattern:

```c
// SPDX-License-Identifier: GPL-2.0-or-later
#include <kunit/test.h>
#include "glob.h"  /* or appropriate header */

static void test_my_feature(struct kunit *test)
{
    KUNIT_EXPECT_EQ(test, 1 + 1, 2);
}

static struct kunit_case my_test_cases[] = {
    KUNIT_CASE(test_my_feature),
    {}
};

static struct kunit_suite my_test_suite = {
    .name = "ksmbd_my_feature_test",
    .test_cases = my_test_cases,
};

kunit_test_suite(my_test_suite);
MODULE_LICENSE("GPL");
```

2. Add the object file to `test/Makefile`:

```makefile
obj-$(CONFIG_KSMBD_KUNIT_TEST) += \
    ...
    ksmbd_test_<name>.o \
    ...
```

3. Run `./test/check_test_registration.sh` to verify registration.

---

## Fuzz Testing

ksmbd provides two layers of fuzz harnesses: kernel-module harnesses
(for syzkaller-style coverage-guided fuzzing) and standalone userspace
harnesses (for libFuzzer).

### Kernel-Module Fuzz Harnesses

Located in `test/fuzz/`, these 48 harnesses build as a kernel module gated
by `CONFIG_KSMBD_FUZZ_TEST`:

```bash
make -C /lib/modules/$(uname -r)/build M=$(pwd) \
    CONFIG_KSMBD_FUZZ_TEST=m modules
```

They are designed for integration with syzkaller or manual testing via
`/sys/kernel/debug/ksmbd/fuzz/`.

### Userspace Fuzz Harnesses (libFuzzer)

Located in `test/fuzz/userspace/`, these extract parsing logic into
standalone programs that run under clang's libFuzzer:

```bash
cd test/fuzz/userspace
make            # Build all targets
make run-all    # Smoke test: 10 seconds per fuzzer
```

**Requirements:** clang with `-fsanitize=fuzzer` support (clang 6.0+).

**Running a single fuzzer:**

```bash
./fuzz_security_descriptor corpus/security_descriptor/ -max_len=4096
./fuzz_compression corpus/compression/ -max_len=65536 -jobs=4
```

Current userspace targets:
- `fuzz_security_descriptor` -- Windows security descriptor parsing
- `fuzz_negotiate_context` -- SMB 3.1.1 negotiate context parsing
- `fuzz_ntlmssp` -- NTLMSSP authentication blob parsing
- `fuzz_compression` -- SMB3 compression/decompression
- `fuzz_create_context` -- SMB2 create context parsing

### Adding a New Fuzz Harness

**Kernel module harness:** Create `test/fuzz/<name>_fuzz.c`, add
`<name>_fuzz.o` to `test/fuzz/Makefile`, then run
`./test/check_test_registration.sh`.

**Userspace harness:** Create `test/fuzz/userspace/fuzz_<name>.c` with a
`LLVMFuzzerTestOneInput` entry point, add a build rule and target name to
`test/fuzz/userspace/Makefile`.

---

## Integration Testing

### ksmbd-torture Framework

The `tests/ksmbd-torture/` directory contains a comprehensive integration
test suite that exercises ksmbd end-to-end using real SMB client tools:

```bash
# Show full usage:
./tests/ksmbd-torture/ksmbd-torture.sh --help

# Run all tests against VM3:
./tests/ksmbd-torture/ksmbd-torture.sh --vm VM3

# Run a specific category:
./tests/ksmbd-torture/ksmbd-torture.sh --vm VM3 --category T01

# Run quick tests only:
./tests/ksmbd-torture/ksmbd-torture.sh --vm VM3 --quick

# Output in TAP format (for CI):
./tests/ksmbd-torture/ksmbd-torture.sh --vm VM3 --tap
```

Exit codes:
- `0` -- All tests passed
- `1` -- One or more tests failed
- `2` -- Server crash detected
- `3` -- Infrastructure error

### VM-Based Testing

The `vm/` directory provides QEMU-based VM infrastructure:

```bash
# Execute a command on a named VM:
./vm/vm-exec-instance.sh VM3 "uname -r"

# Run smbtorture-based tests (extended suite):
./vm/smbtorture-extended-tcp-guest.sh
```

VM fleet layout:
- VM3: SSH port 13022, SMB port 13445
- VM4: SSH port 14022, SMB port 14445

### smbtorture Tests

Samba's `smbtorture` tool provides protocol-level conformance testing:

```bash
# From a VM or host with smbtorture installed:
smbtorture //127.0.0.1/test -U testuser%testpass \
    smb2.create smb2.lock smb2.oplock smb2.compound
```

---

## CI

### GitHub Actions Workflow

The `.github/workflows/kunit.yml` workflow runs on every push and PR to
`master`. It performs three checks:

1. **Registration check** -- `test/check_test_registration.sh` verifies
   every `ksmbd_test_*.c` and `*_fuzz.c` file is listed in its Makefile.
2. **Kernel compile check** -- Builds ksmbd with `CONFIG_KSMBD_KUNIT_TEST=y`
   inside a Linux kernel source tree to verify test code compiles.
3. **Userspace fuzz compile check** -- Builds all libFuzzer targets with
   clang to verify harness code compiles.

**Note:** Full KUnit execution under kunit.py requires a compatible kernel
tree and UML support. The CI workflow performs build-only verification when
runtime execution is not available.

### Interpreting CI Results

- **Green check** -- All test files are registered, all code compiles.
- **Red X on registration** -- A `.c` file was added without updating its
  Makefile. Fix: add the `.o` entry.
- **Red X on compile** -- A test file has a build error. Check the build
  log for the specific error and file.

---

## Test Architecture

### Three Test Tiers

```
Tier 1: KUnit (Unit Tests)
    - Run in-kernel (UML or real hardware)
    - Test individual functions and code paths
    - 144+ test files, ~66,000 lines of test code
    - Fast: seconds to minutes

Tier 2: Fuzz Testing
    - Kernel harnesses (syzkaller): 48 harnesses in test/fuzz/
    - Userspace harnesses (libFuzzer): 5 targets in test/fuzz/userspace/
    - Find crashes, memory errors, undefined behavior
    - Duration: minutes to hours (or continuous)

Tier 3: Integration (ksmbd-torture)
    - Full end-to-end testing with real SMB clients
    - Requires running ksmbd server in a VM
    - Tests protocol compliance, error handling, concurrency
    - Duration: minutes to hours depending on scope
```

### The VISIBLE_IF_KUNIT Pattern

Many ksmbd functions are `static` in production builds but need to be
callable from KUnit test modules. The `VISIBLE_IF_KUNIT` pattern handles
this:

```c
/* In the production .c file: */
#if IS_ENABLED(CONFIG_KUNIT)
#include <kunit/visibility.h>
#else
#define VISIBLE_IF_KUNIT static
#define EXPORT_SYMBOL_IF_KUNIT(sym)
#endif

VISIBLE_IF_KUNIT int my_internal_function(int x)
{
    return x + 1;
}
EXPORT_SYMBOL_IF_KUNIT(my_internal_function);
```

When `CONFIG_KUNIT` is enabled, `<kunit/visibility.h>` defines:
- `VISIBLE_IF_KUNIT` as empty (non-static, visible to other modules)
- `EXPORT_SYMBOL_IF_KUNIT(sym)` as `EXPORT_SYMBOL_NS_GPL(sym, EXPORTED_FOR_KUNIT_TESTING)`

When `CONFIG_KUNIT` is disabled:
- `VISIBLE_IF_KUNIT` becomes `static` (function is file-scoped as normal)
- `EXPORT_SYMBOL_IF_KUNIT(sym)` expands to nothing

This ensures zero overhead in production kernels while allowing test
modules to call internal functions directly.

### File Naming Conventions

| Directory              | Pattern                  | Purpose                       |
|------------------------|--------------------------|-------------------------------|
| `test/`                | `ksmbd_test_*.c`         | KUnit test modules            |
| `test/`                | `Makefile`               | KUnit test build registration |
| `test/`                | `kunit.kunitconfig`      | kunit.py kernel config        |
| `test/fuzz/`           | `*_fuzz.c`               | Kernel fuzz harnesses         |
| `test/fuzz/`           | `Makefile`               | Kernel fuzz build registration|
| `test/fuzz/userspace/` | `fuzz_*.c`               | Userspace libFuzzer targets   |
| `tests/ksmbd-torture/` | `ksmbd-torture.sh`       | Integration test entry point  |
| `tests/ksmbd-torture/suites/` | `*.sh`            | Individual test suites        |
| `tests/ksmbd-torture/tests/`  | `*.sh`            | Individual test cases         |
