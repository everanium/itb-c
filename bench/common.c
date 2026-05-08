/*
 * common.c — shared bench scaffolding for the C binding.
 *
 * Implements the env-var probes, the xorshift64* random fill, and the
 * convergence-measure / report-line emitter consumed by bench_single.c
 * and bench_triple.c. See common.h for the externally-visible surface.
 *
 * Timing uses clock_gettime(CLOCK_MONOTONIC, ...) (POSIX). Output line
 * format mirrors the Rust / D / Python bench harnesses:
 *
 *   <name padded to 60>   <iters>   <ns_per_op> ns/op   <mb_per_s> MB/s
 */

/* Feature-test macro — required to expose clock_gettime / CLOCK_MONOTONIC
 * under glibc when the binding compiles at -std=c17 (which sets a strict
 * conforming mode that hides POSIX-only declarations by default). */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "common.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

const char *const PRIMITIVES_CANONICAL[] = {
    "areion256",
    "areion512",
    "blake2b256",
    "blake2b512",
    "blake2s",
    "blake3",
    "aescmac",
    "siphash24",
    "chacha20",
};
const size_t PRIMITIVES_CANONICAL_LEN =
    sizeof(PRIMITIVES_CANONICAL) / sizeof(PRIMITIVES_CANONICAL[0]);

/* ----- Env-var probes ------------------------------------------------ */

int env_nonce_bits(int default_value) {
    const char *v = getenv("ITB_NONCE_BITS");
    if (v == NULL || v[0] == '\0') {
        return default_value;
    }
    if (strcmp(v, "128") == 0) return 128;
    if (strcmp(v, "256") == 0) return 256;
    if (strcmp(v, "512") == 0) return 512;
    fprintf(stderr,
            "ITB_NONCE_BITS=%s invalid (expected 128/256/512); using %d\n",
            v, default_value);
    return default_value;
}

int env_lock_seed(void) {
    const char *v = getenv("ITB_LOCKSEED");
    if (v == NULL || v[0] == '\0') {
        return 0;
    }
    if (strcmp(v, "0") == 0) {
        return 0;
    }
    return 1;
}

const char *env_filter(void) {
    const char *v = getenv("ITB_BENCH_FILTER");
    if (v == NULL || v[0] == '\0') {
        return NULL;
    }
    return v;
}

double env_min_seconds(void) {
    const char *v = getenv("ITB_BENCH_MIN_SEC");
    if (v == NULL || v[0] == '\0') {
        return 5.0;
    }
    char *endp = NULL;
    errno = 0;
    double f = strtod(v, &endp);
    if (errno != 0 || endp == v || (endp != NULL && *endp != '\0') || f <= 0.0) {
        fprintf(stderr,
                "ITB_BENCH_MIN_SEC=%s invalid (expected positive float); using 5.0\n",
                v);
        return 5.0;
    }
    return f;
}

/* ----- xorshift64* random fill -------------------------------------- */

/* Per-process counter so successive random_bytes calls within the same
 * nanosecond still diverge. Not thread-safe; the bench harness is
 * single-threaded by design (libitb's worker pool absorbs whatever
 * parallelism the case body exposes). */
static uint64_t random_counter = 0;

static uint64_t monotonic_nanos(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0xDEADBEEFCAFEF00DULL;
    }
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

void random_bytes(uint8_t *out, size_t n) {
    if (out == NULL || n == 0) {
        return;
    }
    random_counter += 1;
    uint64_t state = (monotonic_nanos() * 0x9E3779B97F4A7C15ULL)
                     + random_counter
                     + 0xBF58476D1CE4E5B9ULL;
    if (state == 0) {
        state = 0xDEADBEEFCAFEF00DULL;
    }
    size_t i = 0;
    while (i < n) {
        /* xorshift64* — adequate for non-cryptographic test fill. */
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        uint64_t v = state * 0x2545F4914F6CDD1DULL;
        size_t take = (n - i) < 8 ? (n - i) : 8;
        for (size_t k = 0; k < take; k++) {
            out[i + k] = (uint8_t)((v >> (8 * k)) & 0xFF);
        }
        i += take;
    }
}

uint8_t *random_bytes_alloc(size_t n) {
    if (n == 0) {
        return NULL;
    }
    uint8_t *buf = (uint8_t *)malloc(n);
    if (buf == NULL) {
        return NULL;
    }
    random_bytes(buf, n);
    return buf;
}

/* ----- Heap-allocated formatted string ------------------------------ */

char *bench_strdup_fmt(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    va_list ap2;
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) {
        va_end(ap2);
        fprintf(stderr, "bench_strdup_fmt: vsnprintf failed\n");
        abort();
    }
    char *buf = (char *)malloc((size_t)n + 1u);
    if (buf == NULL) {
        va_end(ap2);
        fprintf(stderr, "bench_strdup_fmt: out of memory\n");
        abort();
    }
    int m = vsnprintf(buf, (size_t)n + 1u, fmt, ap2);
    va_end(ap2);
    if (m < 0 || m != n) {
        fprintf(stderr, "bench_strdup_fmt: second vsnprintf disagreed\n");
        abort();
    }
    return buf;
}

/* ----- Substring containment ---------------------------------------- */

static int contains(const char *haystack, const char *needle) {
    if (needle == NULL || needle[0] == '\0') {
        return 1;
    }
    if (haystack == NULL) {
        return 0;
    }
    return strstr(haystack, needle) != NULL ? 1 : 0;
}

/* ----- Single-case measurement -------------------------------------- */

/* Convergence policy mirrors common.d / common.rs / common.py:
 *
 *   1) Warm-up — one iteration to hit cache / cold-start transients
 *      before the measured loop.
 *   2) Measurement — keep doubling the iteration count until the
 *      measured wall-clock duration meets min_seconds. Iteration
 *      count is capped at 1 << 24 so a very fast op cannot escalate
 *      past that ceiling for one batch.
 *   3) Report — final batch's total ns / iters → ns/op; payload_bytes
 *      / ns_per_op → MB/s.
 */
static void measure(bench_case_t *c, double min_seconds) {
    /* Warm-up — one iteration. */
    c->run(c->ctx, 1);

    int64_t min_ns = (int64_t)(min_seconds * 1.0e9);
    uint64_t iters = 1;
    int64_t elapsed_ns = 0;

    for (;;) {
        struct timespec t0;
        struct timespec t1;
        if (clock_gettime(CLOCK_MONOTONIC, &t0) != 0) {
            fprintf(stderr, "clock_gettime failed: %s\n", strerror(errno));
            return;
        }
        c->run(c->ctx, iters);
        if (clock_gettime(CLOCK_MONOTONIC, &t1) != 0) {
            fprintf(stderr, "clock_gettime failed: %s\n", strerror(errno));
            return;
        }
        elapsed_ns = ((int64_t)t1.tv_sec - (int64_t)t0.tv_sec) * 1000000000LL
                     + ((int64_t)t1.tv_nsec - (int64_t)t0.tv_nsec);
        if (elapsed_ns >= min_ns) {
            break;
        }
        if (iters >= (UINT64_C(1) << 24)) {
            break;
        }
        iters *= 2u;
    }

    double ns_per_op = (double)elapsed_ns / (double)iters;
    double mb_per_s = 0.0;
    if (ns_per_op > 0.0) {
        double bytes_per_sec = (double)c->payload_bytes / (ns_per_op / 1.0e9);
        mb_per_s = bytes_per_sec / (double)(1u << 20);
    }
    /* Mirrors `BenchmarkX-8     N    ns/op    MB/s` Go format,
     * column-aligned for human reading. */
    printf("%-60s\t%10llu\t%14.1f ns/op\t%9.2f MB/s\n",
           c->name,
           (unsigned long long)iters,
           ns_per_op,
           mb_per_s);
    fflush(stdout);
}

/* ----- Public driver ------------------------------------------------ */

void run_all(bench_case_t *cases, size_t n_cases) {
    const char *flt = env_filter();
    double min_seconds = env_min_seconds();

    /* Filter pass — a NULL filter accepts every case. */
    size_t selected = 0;
    for (size_t i = 0; i < n_cases; i++) {
        if (flt == NULL || contains(cases[i].name, flt)) {
            selected++;
        }
    }

    if (selected == 0) {
        fprintf(stderr,
                "no bench cases match filter %s; available:",
                flt == NULL ? "<unset>" : flt);
        for (size_t i = 0; i < n_cases; i++) {
            fprintf(stderr, " %s", cases[i].name);
        }
        fprintf(stderr, "\n");
        /* Free names below. */
    } else {
        size_t payload_bytes = 0;
        for (size_t i = 0; i < n_cases; i++) {
            if (flt == NULL || contains(cases[i].name, flt)) {
                payload_bytes = cases[i].payload_bytes;
                break;
            }
        }
        printf("# benchmarks=%zu payload_bytes=%zu min_seconds=%g\n",
               selected, payload_bytes, min_seconds);
        fflush(stdout);

        for (size_t i = 0; i < n_cases; i++) {
            if (flt == NULL || contains(cases[i].name, flt)) {
                measure(&cases[i], min_seconds);
            }
        }
    }

    /* Free heap-owned name strings. */
    for (size_t i = 0; i < n_cases; i++) {
        free(cases[i].name);
        cases[i].name = NULL;
    }
}
