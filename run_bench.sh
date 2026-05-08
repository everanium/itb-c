#!/usr/bin/env bash
#
# run_bench.sh -- canonical 4-pass bench runner for the C binding.
# Sequentially runs:
#
#   Pass 1: Single Ouroboros, ITB_LOCKSEED unset
#   Pass 2: Triple Ouroboros, ITB_LOCKSEED unset
#   Pass 3: Single Ouroboros, ITB_LOCKSEED=1
#   Pass 4: Triple Ouroboros, ITB_LOCKSEED=1
#
# The bench binaries are produced by `make bench` into
# `bench/build/bench_{single,triple}`. Each pass walks 40 cases at the
# configured 5-second per-case budget; total wall-clock ~30-40 minutes.
#
# Environment variables forwarded to the bench binaries:
#   ITB_NONCE_BITS    nonce width (128 / 256 / 512; default 128)
#   ITB_BENCH_FILTER  substring match against bench-case names
#   ITB_BENCH_MIN_SEC per-case wall-clock budget (default 5.0)
#
# `ITB_LOCKSEED` is managed by this script per pass.
#
# Usage:
#   ./run_bench.sh                  # full 4-pass canonical sweep
#   ./run_bench.sh single           # pass 1 + pass 3 only
#   ./run_bench.sh triple           # pass 2 + pass 4 only
#   ./run_bench.sh --no-lockseed    # pass 1 + pass 2 only
#   ./run_bench.sh --lockseed-only  # pass 3 + pass 4 only

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

if [[ ! -f "$DIST_DIR/libitb.so" ]]; then
    echo "error: libitb.so not found at $DIST_DIR" >&2
    echo "       run \`go build -trimpath -buildmode=c-shared -o $DIST_DIR/libitb.so ./cmd/cshared\`" >&2
    exit 1
fi

BENCH_BIN_DIR="bench/build"
if [[ ! -x "$BENCH_BIN_DIR/bench_single" || ! -x "$BENCH_BIN_DIR/bench_triple" ]]; then
    echo "error: bench binaries missing at $BENCH_BIN_DIR/" >&2
    echo "       run \`make bench\` first" >&2
    exit 1
fi

export LD_LIBRARY_PATH="$DIST_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

run_single=1
run_triple=1
run_no_lockseed=1
run_with_lockseed=1
case "${1:-}" in
    single)            run_triple=0;;
    triple)            run_single=0;;
    --no-lockseed)     run_with_lockseed=0;;
    --lockseed-only)   run_no_lockseed=0;;
    -h|--help)         sed -n '3,30p' "$0"; exit 0;;
    "")                ;;
    *)                 echo "unknown option: $1" >&2; exit 2;;
esac

run_pass() {
    local label="$1"
    local bin="$2"
    local lockseed="$3"
    echo
    echo "===================================================================="
    echo "  $label"
    echo "===================================================================="
    if [[ "$lockseed" == "1" ]]; then
        ITB_LOCKSEED=1 "./$BENCH_BIN_DIR/$bin"
    else
        unset ITB_LOCKSEED
        "./$BENCH_BIN_DIR/$bin"
    fi
}

if [[ $run_no_lockseed -eq 1 && $run_single -eq 1 ]]; then
    run_pass "Pass 1 / 4 -- Single, ITB_LOCKSEED=off" bench_single 0
fi
if [[ $run_no_lockseed -eq 1 && $run_triple -eq 1 ]]; then
    run_pass "Pass 2 / 4 -- Triple, ITB_LOCKSEED=off" bench_triple 0
fi
if [[ $run_with_lockseed -eq 1 && $run_single -eq 1 ]]; then
    run_pass "Pass 3 / 4 -- Single, ITB_LOCKSEED=on" bench_single 1
fi
if [[ $run_with_lockseed -eq 1 && $run_triple -eq 1 ]]; then
    run_pass "Pass 4 / 4 -- Triple, ITB_LOCKSEED=on" bench_triple 1
fi

echo
echo "===================================================================="
echo "  bench passes complete -- update bench/BENCH.md by hand"
echo "===================================================================="
