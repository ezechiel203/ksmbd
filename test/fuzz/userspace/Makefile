# SPDX-License-Identifier: GPL-2.0-or-later
#
# Userspace libFuzzer targets for ksmbd parsing routines.
#
# Requirements:
#   - clang with libFuzzer support (-fsanitize=fuzzer)
#   - Linux x86_64 or aarch64 (for endian.h)
#
# Usage:
#   make                     # Build all fuzz targets
#   make fuzz_compression    # Build a single target
#   make clean               # Remove build artifacts
#   make run-all             # Run each fuzzer for 10 seconds (smoke test)
#
# Running a single fuzzer:
#   ./fuzz_security_descriptor corpus/security_descriptor/ -max_len=4096
#   ./fuzz_compression corpus/compression/ -max_len=65536
#

CC       := clang
CFLAGS   := -fsanitize=fuzzer,address,undefined \
            -g -O1 \
            -fno-omit-frame-pointer \
            -I.

# Additional warnings to catch issues early
CFLAGS   += -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare \
            -Wno-gnu-statement-expression -Wno-gnu-zero-variadic-macro-arguments

TARGETS  := fuzz_security_descriptor \
            fuzz_negotiate_context \
            fuzz_ntlmssp \
            fuzz_compression \
            fuzz_create_context

.PHONY: all clean run-all help

all: $(TARGETS)

fuzz_security_descriptor: fuzz_security_descriptor.c ksmbd_compat.h
	$(CC) $(CFLAGS) -o $@ $<

fuzz_negotiate_context: fuzz_negotiate_context.c ksmbd_compat.h
	$(CC) $(CFLAGS) -o $@ $<

fuzz_ntlmssp: fuzz_ntlmssp.c ksmbd_compat.h
	$(CC) $(CFLAGS) -o $@ $<

fuzz_compression: fuzz_compression.c ksmbd_compat.h
	$(CC) $(CFLAGS) -o $@ $<

fuzz_create_context: fuzz_create_context.c ksmbd_compat.h
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS)
	rm -rf corpus/ crash-* leak-* timeout-* slow-unit-* oom-*

# Smoke test: run each fuzzer for 10 seconds
run-all: $(TARGETS)
	@for t in $(TARGETS); do \
		echo "=== Running $$t for 10 seconds ==="; \
		mkdir -p corpus/$$t; \
		./$$t corpus/$$t/ -max_total_time=10 -max_len=4096 \
			-print_final_stats=1 2>&1 | tail -3; \
		echo ""; \
	done

help:
	@echo "Userspace libFuzzer targets for ksmbd"
	@echo ""
	@echo "Targets:"
	@echo "  all          Build all fuzz targets (default)"
	@echo "  clean        Remove build artifacts and corpus"
	@echo "  run-all      Smoke test: run each fuzzer for 10 seconds"
	@echo ""
	@echo "Individual targets:"
	@for t in $(TARGETS); do \
		echo "  $$t"; \
	done
	@echo ""
	@echo "Example long-running fuzzing session:"
	@echo "  ./fuzz_compression corpus/compression/ -max_len=65536 -jobs=4"
