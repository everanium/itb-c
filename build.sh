#!/usr/bin/env bash
#
# build.sh -- one-step build for the C binding: libitb.so + libitb_c.a.
# Prerequisites (Go, a C17 compiler, GNU make, libcheck for the test
# runner) must be installed separately; see README.md "Prerequisites"
# section.
#
# Usage:
#   ./build.sh             # default build (full asm stack)
#   ./build.sh --noitbasm  # opt out of ITB's chain-absorb asm
#   CC=clang ./build.sh    # override the C compiler

set -eu
set -o pipefail

cd "$(dirname "$0")"
SCRIPT_DIR="$(pwd)"
REPO_ROOT="$(cd ../.. && pwd)"

TAGS=()
case "${1:-}" in
    --noitbasm) TAGS=(-tags=noitbasm); shift;;
    -h|--help)  echo "usage: $0 [--noitbasm]"; exit 0;;
    "")         ;;
    *)          echo "unknown option: $1" >&2; exit 2;;
esac

cd "$REPO_ROOT"
echo "==> building libitb.so${TAGS:+ (with ${TAGS[*]})}"
go build -trimpath "${TAGS[@]}" -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared

cd "$SCRIPT_DIR"
echo "==> cleaning previous build artefacts (make clean)"
make clean
mkdir -p build tests/build bench/build
echo "==> building C binding (make, CC=${CC:-cc})"
make

echo "==> ready: ./run_tests.sh"
