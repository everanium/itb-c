#!/usr/bin/env bash
#
# Fleet entry point for the loop stress harness of the C binding:
# builds the utility with the binding's Makefile (a no-op when it is
# up to date; libitb3.so and the C library are assumed built by
# build.sh) and execs it with every argument passed through.
#
# Usage:
#   ./run_loop.sh --duration 2m --shape both

set -eu
set -o pipefail

cd "$(dirname "$0")"

make loop >/dev/null
exec ./loop/loop "$@"
