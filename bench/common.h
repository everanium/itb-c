/*
 * common.h — shared scaffolding for the C binding's Easy Mode bench
 * binaries.
 *
 * The harness mirrors the Go `testing.B` benchmark style on the
 * itb_ext_test.go / itb3_ext_test.go side: each bench function runs a
 * short warm-up batch to reach steady state, then a measured batch
 * whose total wall-clock time is divided by the iteration count to
 * produce the canonical `ns/op` throughput line. The output line also
 * carries an MB/s figure derived from the configured payload size.
 *
 * Environment variables (mirrored from itb's bitbyte_test.go +
 * extended for Easy Mode):
 *
 *   ITB_NONCE_BITS    process-wide nonce width override; valid values
 *                     128 / 256 / 512. Maps to itb_set_nonce_bits
 *                     before any encryptor is constructed. Default 128.
 *   ITB_LOCKBATCH     non-empty / non-`0` enables Lock Batch (performance
 *                     Lock Soup mode); set with ITB_LOCKSEED. Every Easy
 *                     Mode encryptor additionally calls
 *                     itb_encryptor_set_lock_batch(e, 1). Inert unless
 *                     Lock Soup is engaged via ITB_LOCKSEED. Default off.
 *   ITB_LOCKSEED      when set to a non-empty / non-`0` value, every
 *                     Easy Mode encryptor in this run calls
 *                     itb_encryptor_set_lock_seed(e, 1). The Go side's
 *                     auto-couple invariant then engages BitSoup +
 *                     LockSoup automatically. Default off.
 *   ITB_BENCH_FILTER  substring filter on bench-case names; only cases
 *                     whose name contains the filter run. Default unset.
 *   ITB_BENCH_MIN_SEC minimum measured wall-clock seconds per case.
 *                     Default 5.0 — wide enough to absorb the
 *                     cold-cache / warm-up transient that distorts
 *                     shorter measurement windows on the 16 MiB
 *                     encrypt / decrypt path.
 *
 * Worker count defaults to itb_set_max_workers(0) (auto-detect),
 * matching the Go bench default.
 */

#ifndef ITB_C_BENCH_COMMON_H
#define ITB_C_BENCH_COMMON_H

#include <stddef.h>
#include <stdint.h>

#include "itb.h"

/* Default 16 MiB CSPRNG-filled payload, matching the Go bench / Python
 * bench / Rust bench / D bench surfaces. */
#define BENCH_PAYLOAD_16MB ((size_t)(16u << 20))

/* Canonical PRF-grade primitive order. Mirrored verbatim across every
 * binding's bench harness so cross-language diff comparisons align
 * row-for-row. The three below-spec lab primitives
 * (CRC128, FNV-1a, MD5) are not exposed through the libitb registry
 * and are absent here by construction. */
extern const char *const PRIMITIVES_CANONICAL[];
extern const size_t PRIMITIVES_CANONICAL_LEN;

/* Per-iter callable signature. Accepts a registered context pointer and
 * an iteration count, runs the per-iter body that many times. The
 * harness measures wall-clock time outside the callable. */
typedef void (*bench_run_fn)(void *ctx, uint64_t iters);

/* One bench case: name (heap-owned, freed by run_all on exit) +
 * per-iter callable + opaque context + payload byte count (used to
 * compute the MB/s column). */
typedef struct bench_case {
    char *name;
    bench_run_fn run;
    void *ctx;
    size_t payload_bytes;
} bench_case_t;

/* Reads ITB_NONCE_BITS from the environment with the same 128 / 256 /
 * 512 validation as bitbyte_test.go's TestMain. Falls back to
 * default_value on missing / invalid input (with a stderr diagnostic
 * for the invalid case). */
int env_nonce_bits(int default_value);

/* Returns 1 when ITB_LOCKBATCH is set to a non-empty / non-`0` value, 0
 * otherwise. Enables the Lock Batch performance Lock Soup mode; inert
 * unless Lock Soup is engaged via ITB_LOCKSEED. */
int env_lock_batch(void);

/* Returns 1 when ITB_LOCKSEED is set to a non-empty / non-`0` value, 0
 * otherwise. */
int env_lock_seed(void);

/* Returns the optional substring filter for bench-case names from
 * ITB_BENCH_FILTER, or NULL when the variable is unset or empty. The
 * returned pointer is owned by libc's getenv table and must not be
 * freed by the caller. */
const char *env_filter(void);

/* Returns the minimum wall-clock seconds the measured iter loop should
 * take, read from ITB_BENCH_MIN_SEC (default 5.0). The runner keeps
 * doubling iteration count until the measured run reaches this
 * threshold, mirroring Go's `-benchtime=Ns` semantics. */
double env_min_seconds(void);

/* Fills `out` with `n` non-deterministic test bytes via a
 * clock-seeded xorshift64* LCG. The bench harness does not require
 * cryptographic strength here, only that the payload is non-uniform
 * and changes between runs so a primitive cannot collapse on a
 * constant input. */
void random_bytes(uint8_t *out, size_t n);

/* Allocates `n` non-deterministic test bytes on the heap; caller frees
 * with free(). Returns NULL on allocation failure. */
uint8_t *random_bytes_alloc(size_t n);

/* snprintf-style helper that returns a heap-allocated string. Caller
 * frees with free(). Aborts on allocation failure (a benign infallible
 * surface for the bench setup path). */
char *bench_strdup_fmt(const char *fmt, ...);

/* Run every case in `cases` and print one Go-bench-style line per case
 * to stdout. Honours ITB_BENCH_FILTER for substring scoping and
 * ITB_BENCH_MIN_SEC for per-case wall-clock budget.
 *
 * Each case's `name` field is freed by run_all before return; the
 * caller must not reference it after the call returns. */
void run_all(bench_case_t *cases, size_t n_cases);

/* Measure a single pre-built case at `min_seconds` threshold and emit
 * one Go-bench-style report line.  Used by the lazy bench runner in
 * bench_wrapper.c — the caller filters and prints the header line
 * itself; this function handles only the measurement + output for one
 * case.  The case's `name` field is NOT freed by this function; the
 * caller owns the lifetime of the case. */
void bench_measure_one(bench_case_t *c, double min_seconds);

#endif /* ITB_C_BENCH_COMMON_H */
