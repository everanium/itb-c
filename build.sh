#!/usr/bin/env bash
#
# build.sh -- one-step build for the C binding: libitb.so + the C
# library + every test binary. Prerequisites (Go, a C11 compiler, GNU
# make) must be installed separately; see README.md "Prerequisites".
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
echo "==> building C binding + tests (make, CC=${CC:-cc})"
make all

echo "==> ready: ./run_tests.sh"
