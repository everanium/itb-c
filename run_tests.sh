#!/usr/bin/env bash
#
# run_tests.sh — Build and run every tests/test_*.c under bindings/c.
#
# Mirrors the per-test-binary discipline of the Ada / D / Rust binding
# test runners: each tests/test_*.c is compiled to its own standalone
# executable in tests/build/, then run in turn. Per-process isolation
# gives every test a fresh libitb global state without needing an
# in-process serial lock.
#
# The Makefile's per-binary pattern rule auto-discovers tests/test_*.c
# via wildcard glob and links each binary against build/libitb_c.a +
# the system `check` unit-testing framework + libitb.so (the latter via
# embedded RPATH so LD_LIBRARY_PATH is unnecessary at runtime).
#
# Usage:
#   ./run_tests.sh
#
# Exit code is 0 when every test binary returns 0, 1 otherwise.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Build the test binaries via the Makefile so the compiler flags and
# pkg-config wiring stay in one place.
make tests >/dev/null

fail=0
pass=0
for bin in tests/build/test_*; do
    [ -x "$bin" ] || continue
    name="$(basename "$bin")"
    if "$bin" >/dev/null 2>&1; then
        printf '  \033[32m✓\033[0m %s\n' "$name"
        pass=$((pass + 1))
    else
        printf '  \033[31m✗\033[0m %s\n' "$name"
        "$bin" 2>&1 | sed 's/^/      /'
        fail=$((fail + 1))
    fi
done

echo
echo "  PASS: $pass"
echo "  FAIL: $fail"
exit "$fail"
