/*
 * bench_util.h — shared timing + reporting helpers for the C binding
 * micro-benchmarks. Wall-clock via clock_gettime(CLOCK_MONOTONIC);
 * output is a fixed-width table:
 *
 *   bench             size     mb_per_sec
 *   message           1 KiB    <n>
 *   ...
 */

#ifndef ITB_BENCH_UTIL_H
#define ITB_BENCH_UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "itb.h"

/* Per-case wall-clock budget (seconds, env: ITB_BENCH_MIN_SEC)
 * and iteration floor. */
#define BENCH_MIN_ITERS 3

static double bench_min_seconds(void)
{
    const char *raw = getenv("ITB_BENCH_MIN_SEC");
    if (raw != NULL && *raw != '\0') {
        double v = strtod(raw, NULL);
        if (v > 0.0) {
            return v;
        }
    }
    return 5.0;
}

/* Reads the bench-shape env vars and builds an itb_opts. Defaults
 * match root Go BENCH3.md so numbers are directly comparable. */
static itb_opts *bench_build_opts(void)
{
    itb_opts *opts = itb_opts_new();
    if (opts == NULL) {
        return NULL;
    }
    const char *nb = getenv("ITB_NONCE_BITS");
    (void)itb_opts_set(opts, "nonceBits", (nb && *nb) ? nb : "512");
    const char *kb = getenv("ITB_KEY_BITS");
    (void)itb_opts_set(opts, "keyBits", (kb && *kb) ? kb : "1024");
    const char *wp = getenv("ITB_WITH_PARALLAX");
    const char *wp_val = (wp && (strcmp(wp, "true") == 0 || strcmp(wp, "1") == 0))
                             ? "true"
                             : "false";
    (void)itb_opts_set(opts, "withParallax", wp_val);
    const char *ww = getenv("ITB_WITH_WRAPPER");
    const char *ww_val = (ww && (strcmp(ww, "true") == 0 || strcmp(ww, "1") == 0))
                             ? "true"
                             : "false";
    (void)itb_opts_set(opts, "withWrapper", ww_val);
    const char *ih = getenv("ITB_INNER_HASH");
    if (ih != NULL && *ih != '\0') {
        (void)itb_opts_set(opts, "innerHash", ih);
    }
    const char *mn = getenv("ITB_MAC_NAME");
    if (mn != NULL && *mn != '\0') {
        (void)itb_opts_set(opts, "macName", mn);
    }
    return opts;
}

static const char *bench_profile_name(const char *fallback)
{
    const char *env = getenv("ITB_PROFILE");
    return (env && *env) ? env : fallback;
}

static double bench_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void bench_header(void)
{
    printf("%-17s %-8s %s\n", "bench", "size", "mb_per_sec");
}

static const char *bench_size_label(size_t size)
{
    static char label[32];
    if (size >= ((size_t)1 << 20)) {
        (void)snprintf(label, sizeof(label), "%zu MiB", size >> 20);
    } else {
        (void)snprintf(label, sizeof(label), "%zu KiB", size >> 10);
    }
    return label;
}

/* Runs fn(ctx) until the wall-clock budget is spent (with an
 * iteration floor + one untimed warm-up), then prints one table row.
 * fn returns 0 on success; a failure aborts the process. */
static void bench_case(const char *name, size_t size,
                       int (*fn)(void *ctx), void *ctx)
{
    if (fn(ctx) != 0) { /* warm-up */
        fprintf(stderr, "bench %s @%zu: warm-up failed: %s\n", name, size,
                itb_last_error());
        exit(1);
    }
    double start = bench_now();
    double elapsed = 0.0;
    size_t iters = 0;
    double budget = bench_min_seconds();
    while (elapsed < budget || iters < BENCH_MIN_ITERS) {
        if (fn(ctx) != 0) {
            fprintf(stderr, "bench %s @%zu: iteration failed: %s\n", name,
                    size, itb_last_error());
            exit(1);
        }
        iters++;
        elapsed = bench_now() - start;
    }
    double mb = (double)size * (double)iters / (1024.0 * 1024.0);
    printf("%-17s %-8s %.1f\n", name, bench_size_label(size), mb / elapsed);
}

#endif /* ITB_BENCH_UTIL_H */
