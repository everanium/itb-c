# ITB C Binding - Easy Mode Benchmark

Two executables (`bench_single`, `bench_triple`) cover the Easy Mode
encryption / decryption surface exposed by the C binding through two
`int main(void)` entry points driven by one shared `common.c` /
`common.h` module:

* `bench_single.c` — Single Ouroboros (mode = 1, 3 seeds + optional
  dedicated lockSeed). Walks the nine PRF-grade primitives plus one
  mixed-primitive variant.
* `bench_triple.c` — Triple Ouroboros (mode = 3, 7 seeds + optional
  dedicated lockSeed). Same nine + one mixed grid as the Single
  binary.

Both binaries pin **1024-bit ITB key width** and **16 MiB
non-deterministic-fill payload**, run four ops per case
(`itb_encryptor_encrypt`, `itb_encryptor_decrypt`,
`itb_encryptor_encrypt_auth`, `itb_encryptor_decrypt_auth`), and emit
a Go-bench-style line per case (`name iters ns/op MB/s`).

The harness is a custom Go-bench-style runner in `common.c` (no
third-party bench framework — `clock_gettime(CLOCK_MONOTONIC, ...)`
and an inline xorshift64\* LCG cover the timing and random-fill
surfaces). One `make bench` invocation produces both binaries.

## Prerequisites

Build the shared library and confirm a C toolchain is available
(GCC ≥ 10 or Clang ≥ 13 satisfies the `-std=c17` baseline used by
the binding's Makefile):

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
cc --version
```

A project-private opt-out tag is available when the 4-lane
chain-absorb wrapper is dead weight (hosts without AVX-512+VL). The
tag disables only the chain-absorb asm; upstream stdlib asm stays
engaged so the per-pixel single Func runs at upstream-asm speed via
`process_cgo`'s nil-`BatchHash` fallback:

```bash
go build -trimpath -tags=noitbasm -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
```

The C binding loads `libitb.so` at link time (`-litb` plus
`-Wl,-rpath,../../dist/linux-amd64`) and resolves it at run time via
the embedded RPATH baked into each bench binary; see the
`bindings/c/Makefile` bench section for the exact link line.

## Run

From the binding root (`bindings/c/`):

```bash
make bench
./bench/build/bench_single
./bench/build/bench_triple
```

The Makefile compiles each `bench/bench_*.c` against
`build/libitb_c.a` + `bench/common.c`, producing one binary per source
file under `bench/build/`. Both binaries land in `bench/build/` after
a successful `make bench`.

For the canonical four-pass sweep that fills [BENCH.md](BENCH.md),
use the wrapper script in the binding root:

```bash
cd bindings/c
make bench
./run_bench.sh                  # full 4-pass canonical sweep
./run_bench.sh single           # passes 1 + 3 (Single Ouroboros only)
./run_bench.sh triple           # passes 2 + 4 (Triple Ouroboros only)
./run_bench.sh --no-lockseed    # passes 1 + 2 only
./run_bench.sh --lockseed-only  # passes 3 + 4 only
```

## Environment variables

| Variable             | Default | Purpose |
|----------------------|---------|---------|
| `ITB_NONCE_BITS`     | `128`   | Process-wide nonce width — `128`, `256`, or `512`. Maps to `itb_set_nonce_bits` before any encryptor is constructed. Mirrors `ITB_NONCE_BITS` from `bitbyte_test.go`. |
| `ITB_LOCKSEED`       | unset   | When set to a non-empty / non-`0` value, every encryptor in the run calls `itb_encryptor_set_lock_seed(e, 1)`. Easy Mode auto-couples `set_bit_soup(1)` + `set_lock_soup(1)`, so no separate flags are needed. The mixed-primitive cases attach a dedicated lockSeed primitive (via `prim_l = "chacha20"`) only under this flag; otherwise `prim_l` is `NULL` so the no-LockSeed bench arm measures the plain mixed-primitive cost. |
| `ITB_BENCH_FILTER`   | unset   | Substring filter on bench-case names — only cases whose name contains the filter are run. Useful when iterating on one primitive / op. |
| `ITB_BENCH_MIN_SEC`  | `5.0`   | Minimum measured wall-clock seconds per case. The runner keeps doubling iteration count until the measured batch reaches the threshold, mirroring Go's `-benchtime=Ns`. The 5-second default absorbs the cold-cache / warm-up transient that distorts shorter measurement windows on the 16 MiB encrypt / decrypt path. |

Worker count is fixed at `itb_set_max_workers(0)` (auto-detect),
matching the Go bench default.

## Examples

Whole grid, default settings (128-bit nonces, no lockSeed):

```bash
./bench/build/bench_single
```

512-bit nonces with the dedicated lockSeed channel + auto-coupled
overlay:

```bash
ITB_NONCE_BITS=512 ITB_LOCKSEED=1 ./bench/build/bench_triple
```

Just the BLAKE3 row of the Single grid:

```bash
ITB_BENCH_FILTER=blake3_1024bit ./bench/build/bench_single
```

Only the encrypt-with-MAC ops across every primitive in the Triple
grid, with a longer 10-second per-case budget for tighter confidence
intervals:

```bash
ITB_BENCH_FILTER=encrypt_auth_16mb ITB_BENCH_MIN_SEC=10 \
    ./bench/build/bench_triple
```

Just the mixed-primitive cases on the Single side:

```bash
ITB_BENCH_FILTER=mixed ./bench/build/bench_single
```

## Output format

```
# easy_single primitives=9 key_bits=1024 mac=hmac-blake3 nonce_bits=128 lockseed=off workers=auto
# benchmarks=40 payload_bytes=16777216 min_seconds=5
bench_single_aescmac_1024bit_encrypt_16mb               4    493210110.0 ns/op    32.44 MB/s
bench_single_aescmac_1024bit_decrypt_16mb               4    488104225.0 ns/op    32.78 MB/s
...
```

The four columns are:

1. Bench-case name (matches the `BenchmarkSingle*` /
   `BenchmarkTriple*` Go cohort, snake-cased).
2. Iteration count chosen to reach `ITB_BENCH_MIN_SEC`.
3. Per-iter wall-clock cost in nanoseconds.
4. Throughput in MiB/s, derived from `payload_bytes / ns_per_op`.

Comparison with the Go bench cohort goes via the MB/s column — the
throughput figure is the most direct cross-language signal for how
much overhead the C binding adds on top of the underlying libitb call
path.

## Expected runtime

At the default `ITB_BENCH_MIN_SEC=5`, each pass walks 40 cases (9
single-primitive + 1 mixed × 4 ops) and converges per case in 5–15
wall-clock seconds depending on the primitive's per-byte cost. A
full pass therefore lands at 5–10 minutes; the four canonical passes
(Single ±LockSeed, Triple ±LockSeed) fill BENCH.md in ~30 minutes of
total wall-clock time. Filter to a single primitive
(`ITB_BENCH_FILTER=blake3_1024bit`) for ~1-minute spot-check runs.

## Recorded results

A snapshot of the four canonical pass results (Single + Triple, each
with and without `ITB_LOCKSEED=1`) on Intel Core i7-11700K is
collected in [BENCH.md](BENCH.md). The same file briefly discusses
the FFI overhead the binding leaves on top of the native Go path
through the `extern "C"` declarations the wrapper uses for every
`ITB_*` symbol. Pointer back to the binding's top-level
[README.md](../README.md) for the broader Easy Mode surface
documentation.
