#!/usr/bin/env bash
#
# build.sh -- one-step build for the C binding: libitb3.so + the C
# library + every test binary. Prerequisites (Go, a C11 compiler, GNU
# make) must be installed separately; see README.md "Prerequisites".
#
# Every artefact this binding owns is removed first, so nothing the
# build produces can be a leftover from an earlier invocation.
#
# Usage:
#   ./build.sh             # default build (full asm stack)
#   ./build.sh --noitbasm  # opt out of ITB's SIMD asm kernels
#   CC=clang ./build.sh    # override the C compiler
#   ITB_SKIP_CLEAN=1 ./build.sh   # keep existing artefacts

set -eu
set -o pipefail

cd "$(dirname "$0")"
SCRIPT_DIR="$(pwd -P)"
REPO_ROOT="$(cd ../.. && pwd -P)"

TAGS=()
case "${1:-}" in
    --noitbasm) TAGS=(-tags=noitbasm); shift;;
    -h|--help)  echo "usage: $0 [--noitbasm]"; exit 0;;
    "")         ;;
    *)          echo "unknown option: $1" >&2; exit 2;;
esac

# ---- Clean ----------------------------------------------------------
# Artefacts this binding owns. The Go shared library under
# dist/linux-amd64/ is shared by every binding and stays untouched;
# bindings/c/build/libitb3_c.a is regenerated below, and the sibling
# bindings that link it rebuild it through their own make invocation.
CLEAN_TARGETS=(
    build                 # library objects, .a / .so, asan + ubsan trees
    tests/build           # per-test binaries, asan + ubsan trees
    benches/build         # bench binaries
    eitb/eitb             # eitb CLI
    scan-build-out        # static-analyser report tree
    coverage              # gcov report tree
)

clean_artefacts() {
    local rel abs tracked

    # A build artefact is never tracked, so a hit here means the list
    # above is wrong. Abort rather than delete a source file.
    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        tracked="$(git ls-files -- "${CLEAN_TARGETS[@]}")"
        if [ -n "$tracked" ]; then
            echo "clean: tracked files inside the clean scope:" >&2
            printf '%s\n' "$tracked" | sed 's/^/    /' >&2
            exit 1
        fi
    fi

    for rel in "${CLEAN_TARGETS[@]}"; do
        abs="$(readlink -m -- "$SCRIPT_DIR/$rel")"
        case "$abs" in
            "$SCRIPT_DIR"/?*) ;;
            *) echo "clean: '$rel' escapes $SCRIPT_DIR ($abs)" >&2; exit 1;;
        esac
        [ -e "$abs" ] || continue
        echo "[clean] rm -rf $abs"
        rm -rf -- "$abs"
    done
}

if [ "${ITB_SKIP_CLEAN:-0}" = "1" ]; then
    echo "==> ITB_SKIP_CLEAN=1 -- keeping existing artefacts"
else
    echo "==> cleaning previous artefacts"
    clean_artefacts
fi

cd "$REPO_ROOT"
echo "==> building libitb3.so${TAGS:+ (with ${TAGS[*]})}"
go build -trimpath "${TAGS[@]}" -buildmode=c-shared \
    -o dist/linux-amd64/libitb3.so ./cmd/cshared

cd "$SCRIPT_DIR"
echo "==> building C binding + tests + eitb (make, CC=${CC:-cc})"
make all eitb

echo "==> ready: ./run_tests.sh"
