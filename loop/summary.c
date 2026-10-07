/*
 * The final summary in both renderings, and the two measurements it
 * folds in that are not per-worker counters: the process resident
 * set and the shared library's pool counters.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "loop.h"

/* ------------------------------------------------------------------ */
/* Resident set                                                        */
/* ------------------------------------------------------------------ */

/* Parses one "Vm...:   1234 kB" line of /proc/self/status into
 * bytes; zero on any parse failure. */
static uint64_t status_kb(const char *line)
{
    const char *p = strchr(line, ':');
    if (p == NULL) {
        return 0;
    }
    unsigned long long kb = strtoull(p + 1, NULL, 10);
    return (uint64_t)kb * 1024u;
}

/* The process's current resident set and its high-water mark in
 * bytes, from /proc/self/status (VmRSS and VmHWM, reported in kB).
 * Both are zero on a platform without that file; the figures are
 * informational and never enter the verdict. */
void read_rss(uint64_t *current, uint64_t *peak)
{
    *current = 0;
    *peak = 0;
    FILE *f = fopen("/proc/self/status", "r");
    if (f == NULL) {
        return;
    }
    char line[256];
    while (fgets(line, sizeof(line), f) != NULL) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            *current = status_kb(line);
        } else if (strncmp(line, "VmHWM:", 6) == 0) {
            *peak = status_kb(line);
        }
    }
    fclose(f);
}

/* ------------------------------------------------------------------ */
/* Pool counters                                                       */
/* ------------------------------------------------------------------ */

/* Pool counters. The shared library keeps process-wide monotonic
 * totals at every pool checkout of its cipher core: per hash-array
 * tier the starter width, checkouts, constructor misses, regrow
 * replacements and bytes allocated; for the scratch byte pool and
 * the parallax chunk pool the checkouts, constructor misses, regrows
 * and regrow bytes. Two snapshots bracketing the main loop are
 * differenced into per-run hit / miss figures that tell whether a
 * pool keeps its items warm between calls or evicts them across GC
 * cycles. The slot layout is read from the library: slot 0 carries
 * the tier count T, tier i occupies the five slots at 1 + 5*i, and
 * the two byte pools occupy the eight slots at 1 + 5*T; the buffer
 * is sized from the binding's length query, never from a constant. */
int pool_snapshot_alloc(int64_t **out, size_t *len)
{
    *len = itb_pool_stats_len();
    if (*len == 0) {
        return -1;
    }
    *out = calloc(*len, sizeof(int64_t));
    return *out == NULL ? -1 : 0;
}

int pool_snapshot_take(int64_t *dst, size_t len)
{
    size_t written = 0;
    return itb_pool_stats(dst, len, &written) == ITB_STATUS_OK ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* Summary                                                             */
/* ------------------------------------------------------------------ */

/* The differenced pool figures of one run. */
struct pool_delta {
    int64_t tiers;
    int64_t starter[64];
    int64_t get[64];
    int64_t new_[64];
    int64_t regrow[64];
    int64_t new_bytes[64];
    int64_t buf_get, buf_new, buf_regrow, buf_regrow_bytes;
    int64_t chunk_get, chunk_new, chunk_regrow, chunk_regrow_bytes;
};

static void pool_diff(const struct run_state *r, struct pool_delta *d)
{
    memset(d, 0, sizeof(*d));
    if (r->pool_warmup == NULL || r->pool_steady == NULL || r->pool_len < 9) {
        return;
    }
    const int64_t *w = r->pool_warmup;
    const int64_t *s = r->pool_steady;
    int64_t tiers = s[0];
    if (tiers < 0 || tiers > 64 || (size_t)(1 + 5 * tiers + 8) > r->pool_len) {
        return;
    }
    d->tiers = tiers;
    for (int64_t i = 0; i < tiers; i++) {
        size_t base = (size_t)(1 + 5 * i);
        d->starter[i] = s[base + 0];
        d->get[i] = s[base + 1] - w[base + 1];
        d->new_[i] = s[base + 2] - w[base + 2];
        d->regrow[i] = s[base + 3] - w[base + 3];
        d->new_bytes[i] = s[base + 4] - w[base + 4];
    }
    size_t tail = (size_t)(1 + 5 * tiers);
    d->buf_get = s[tail + 0] - w[tail + 0];
    d->buf_new = s[tail + 1] - w[tail + 1];
    d->buf_regrow = s[tail + 2] - w[tail + 2];
    d->buf_regrow_bytes = s[tail + 3] - w[tail + 3];
    d->chunk_get = s[tail + 4] - w[tail + 4];
    d->chunk_new = s[tail + 5] - w[tail + 5];
    d->chunk_regrow = s[tail + 6] - w[tail + 6];
    d->chunk_regrow_bytes = s[tail + 7] - w[tail + 7];
}

/* Misses over checkouts as a percentage; zero when nothing was
 * checked out. */
static double miss_percent(int64_t miss, int64_t get)
{
    if (get <= 0) {
        return 0.0;
    }
    return 100.0 * (double)miss / (double)get;
}

/* Writes s as a JSON string literal with the escapes JSON requires. */
static void json_string(const char *s)
{
    putchar('"');
    for (; *s != '\0'; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
        case '"':
            fputs("\\\"", stdout);
            break;
        case '\\':
            fputs("\\\\", stdout);
            break;
        case '\n':
            fputs("\\n", stdout);
            break;
        case '\r':
            fputs("\\r", stdout);
            break;
        case '\t':
            fputs("\\t", stdout);
            break;
        default:
            if (c < 0x20) {
                printf("\\u%04x", c);
            } else {
                putchar(c);
            }
        }
    }
    putchar('"');
}

/* The effective GC percentage as the runtime reports it: the query
 * form of the setter (a set-and-restore round trip inside the
 * library) so the field is the same whether the value came from the
 * flag, the environment, or the runtime default. */
static int effective_gogc(int flag)
{
    if (flag > 0) {
        return flag;
    }
    return (int)itb_set_gc_percent(-1);
}

/* Output contract. Both renderings are shared with the Go harness and
 * every other binding's loop utility field for field: the same lines
 * in the same order, the same keys in the same order, floats with a
 * fixed number of decimals so the JSON is byte-identical across
 * implementations. The Go harness alone adds its runtime-internal
 * lines after rss: and its runtime-internal keys after
 * parallax_chunk_pool; nothing here reproduces them because nothing
 * they read is reachable through the C ABI. */
int final_summary(struct run_state *r, int64_t elapsed_ns)
{
    const struct config *cfg = &r->cfg;
    int64_t total_iters = 0;
    int64_t total_enc = 0;
    int64_t total_dec = 0;
    int64_t nanos_enc = 0;
    int64_t nanos_dec = 0;
    int errors = 0;
    for (int i = 0; i < cfg->workers; i++) {
        const struct worker *w = &r->workers[i];
        total_iters += atomic_load(&w->iters);
        total_enc += atomic_load(&w->bytes_enc);
        total_dec += atomic_load(&w->bytes_dec);
        nanos_enc += atomic_load(&w->nanos_enc);
        nanos_dec += atomic_load(&w->nanos_dec);
        if (w->failed) {
            errors++;
        }
    }

    /* Throughput. Per-direction throughput divides the sum of every
     * worker's wall time in that direction by the worker count — the
     * equivalent single-stream wall time under N-way concurrency — so
     * each direction reports the aggregate rate it sustained rather
     * than collapsing to combined/2 (every iteration moves equal
     * encrypt and decrypt bytes, so a total-elapsed denominator would
     * give both directions the same figure). The combined rate keeps
     * total elapsed as the one-glance overall figure. */
    int64_t avg_enc = nanos_enc > 0 ? nanos_enc / cfg->workers : 0;
    int64_t avg_dec = nanos_dec > 0 ? nanos_dec / cfg->workers : 0;

    int64_t rss_delta = (int64_t)r->rss_final - (int64_t)r->rss_warmup;
    double rss_growth = 0.0;
    if (r->rss_warmup > 0) {
        rss_growth = 100.0 * (double)rss_delta / (double)r->rss_warmup;
    }

    struct pool_delta pd;
    pool_diff(r, &pd);

    bool pass = errors == 0;
    long long rekeys = (long long)atomic_load(&r->rekeys);
    long long cycles = (long long)atomic_load(&r->blob_cycles);
    int gomaxprocs = (int)itb_set_gomaxprocs(0);
    const char *stream_profile = r->stream_pipe != NULL ? r->stream_profile : "";
    const char *msg_profile = r->msg_pipe != NULL ? r->msg_profile : "";

    if (cfg->json_output) {
        printf("{\"duration_seconds\":%.3f", (double)elapsed_ns / 1e9);
        printf(",\"iterations\":%lld", (long long)total_iters);
        printf(",\"per_worker_iterations\":[");
        for (int i = 0; i < cfg->workers; i++) {
            printf("%s%lld", i > 0 ? "," : "", (long long)atomic_load(&r->workers[i].iters));
        }
        printf("]");
        printf(",\"bytes_encrypted\":%lld", (long long)total_enc);
        printf(",\"bytes_decrypted\":%lld", (long long)total_dec);
        printf(",\"encrypt_mb_per_sec\":%.1f", mb_per_sec(total_enc, avg_enc));
        printf(",\"decrypt_mb_per_sec\":%.1f", mb_per_sec(total_dec, avg_dec));
        printf(",\"combined_mb_per_sec\":%.1f", mb_per_sec(total_enc + total_dec, elapsed_ns));
        printf(",\"rekeys\":%lld", rekeys);
        printf(",\"blob_cycles\":%lld", cycles);
        printf(",\"worker_errors\":[");
        {
            int n = 0;
            for (int i = 0; i < cfg->workers; i++) {
                if (r->workers[i].failed) {
                    if (n++ > 0) {
                        putchar(',');
                    }
                    json_string(r->workers[i].error);
                }
            }
        }
        printf("]");
        printf(",\"verdict\":\"%s\"", pass ? "PASS" : "FAIL");
        printf(",\"shape\":\"%s\"", shape_name(cfg->shape));
        printf(",\"stream_profile\":");
        json_string(stream_profile);
        printf(",\"message_profile\":");
        json_string(msg_profile);
        printf(",\"hash\":");
        json_string(cfg->hash);
        printf(",\"mac\":");
        json_string(cfg->mac);
        printf(",\"payload_bytes\":%lld", (long long)cfg->payload);
        printf(",\"payload_mode\":\"%s\"", payload_mode_name(cfg->payload_mode));
        printf(",\"seed\":%llu", (unsigned long long)cfg->seed);
        printf(",\"key_bits\":%d", cfg->key_bits);
        printf(",\"nonce_bits\":%d", cfg->nonce_bits);
        printf(",\"blob_mode\":%d", cfg->blob_mode);
        printf(",\"drbg\":");
        json_string(cfg->drbg);
        printf(",\"drbg_auto_tier\":");
        const char *auto_tier = itb_drbg_auto_tier();
        json_string(auto_tier != NULL ? auto_tier : "");
        printf(",\"chunk_size_bytes\":%lld", (long long)cfg->chunk_size);
        printf(",\"barrier_fill\":%d", cfg->barrier_fill);
        printf(",\"parallax\":\"%s\"", on_off(cfg->parallax));
        printf(",\"wrapper\":\"%s\"", on_off(cfg->wrapper));
        printf(",\"goroutines_requested\":%d", cfg->workers_requested);
        printf(",\"goroutines\":%d", cfg->workers);
        printf(",\"concurrency\":\"%s\"", LOOP_CONCURRENCY);
        printf(",\"gogc\":\"%d\"", effective_gogc(cfg->gogc));
        printf(",\"memlimit_bytes\":%lld", (long long)cfg->memlimit);
        printf(",\"gomaxprocs\":%d", gomaxprocs);
        printf(",\"microbatch_tiers\":");
        json_string(policy_label(getenv("ITB_MICROBATCH_TIERS")));
        printf(",\"hashpool_starters\":");
        json_string(policy_label(getenv("ITB_HASHPOOL_STARTERS")));
        printf(",\"rss_warmup_bytes\":%llu", (unsigned long long)r->rss_warmup);
        printf(",\"rss_peak_bytes\":%llu", (unsigned long long)r->rss_peak);
        printf(",\"rss_final_bytes\":%llu", (unsigned long long)r->rss_final);
        printf(",\"rss_growth_percent\":%.2f", rss_growth);
        printf(",\"hash_pool_tiers\":[");
        {
            int n = 0;
            for (int64_t i = 0; i < pd.tiers; i++) {
                if (pd.starter[i] == 0) {
                    continue;
                }
                printf("%s{\"tier\":%lld,\"starter\":%lld,\"get\":%lld,\"new\":%lld,"
                       "\"regrow\":%lld,\"new_bytes\":%lld,\"miss_percent\":%.2f}",
                       n++ > 0 ? "," : "", (long long)i, (long long)pd.starter[i],
                       (long long)pd.get[i], (long long)pd.new_[i], (long long)pd.regrow[i],
                       (long long)pd.new_bytes[i],
                       miss_percent(pd.new_[i] + pd.regrow[i], pd.get[i]));
            }
        }
        printf("]");
        printf(",\"buf_pool\":{\"get\":%lld,\"new\":%lld,\"regrow\":%lld,\"regrow_bytes\":%lld,"
               "\"miss_percent\":%.2f}",
               (long long)pd.buf_get, (long long)pd.buf_new, (long long)pd.buf_regrow,
               (long long)pd.buf_regrow_bytes, miss_percent(pd.buf_regrow, pd.buf_get));
        printf(",\"parallax_chunk_pool\":{\"get\":%lld,\"new\":%lld,\"regrow\":%lld,"
               "\"regrow_bytes\":%lld,\"miss_percent\":%.2f}",
               (long long)pd.chunk_get, (long long)pd.chunk_new, (long long)pd.chunk_regrow,
               (long long)pd.chunk_regrow_bytes, miss_percent(pd.chunk_regrow, pd.chunk_get));
        printf("}\n");
        return pass ? 0 : 1;
    }

    char a[32], b[32], c[32], d[32];
    log_line("=== FINAL ===");
    human_duration((elapsed_ns + 500000) / 1000000 * 1000000, a, sizeof(a));
    log_line("  duration: %s", a);
    {
        char parts[LOOP_MAX_WORKERS * 24];
        size_t used = 0;
        parts[0] = '\0';
        for (int i = 0; i < cfg->workers; i++) {
            (void)snprintf(parts + used, sizeof(parts) - used, "%s%lld",
                           i > 0 ? " + " : "", (long long)atomic_load(&r->workers[i].iters));
            used = strlen(parts);
        }
        log_line("  iterations: %s = %lld total", parts, (long long)total_iters);
    }
    human_rate(total_enc, avg_enc, a, sizeof(a));
    human_rate(total_dec, avg_dec, b, sizeof(b));
    human_rate(total_enc + total_dec, elapsed_ns, c, sizeof(c));
    log_line("  throughput: encrypt %s, decrypt %s, combined %s", a, b, c);
    human_bytes(total_enc, a, sizeof(a));
    human_bytes(total_dec, b, sizeof(b));
    log_line("  bytes: %s encrypted, %s decrypted", a, b);
    log_line("  data integrity: %lld/%lld PASS", (long long)total_iters, (long long)total_iters);
    log_line("  concurrency: %s, workers %d (requested %d)", LOOP_CONCURRENCY,
             cfg->workers, cfg->workers_requested);
    human_bytes((int64_t)r->rss_warmup, a, sizeof(a));
    human_bytes((int64_t)r->rss_peak, b, sizeof(b));
    human_bytes((int64_t)r->rss_final, c, sizeof(c));
    human_bytes_signed(rss_delta, d, sizeof(d));
    log_line("  rss: warmup %s, peak %s, final %s (delta %s, %.1f%% growth)", a, b, c, d, rss_growth);
    for (int64_t i = 0; i < pd.tiers; i++) {
        if (pd.starter[i] == 0) {
            continue;
        }
        human_bytes(pd.new_bytes[i], a, sizeof(a));
        log_line("  hash pool tier %lld (starter %lld): get %lld, miss %lld (new %lld + regrow %lld), miss %.2f%%, %s allocated",
                 (long long)i, (long long)pd.starter[i], (long long)pd.get[i],
                 (long long)(pd.new_[i] + pd.regrow[i]), (long long)pd.new_[i],
                 (long long)pd.regrow[i], miss_percent(pd.new_[i] + pd.regrow[i], pd.get[i]), a);
    }
    human_bytes(pd.buf_regrow_bytes, a, sizeof(a));
    log_line("  buf pool: get %lld, regrow %lld (of which fresh %lld), miss %.2f%%, %s regrown",
             (long long)pd.buf_get, (long long)pd.buf_regrow, (long long)pd.buf_new,
             miss_percent(pd.buf_regrow, pd.buf_get), a);
    human_bytes(pd.chunk_regrow_bytes, a, sizeof(a));
    log_line("  parallax chunk pool: get %lld, regrow %lld (of which fresh %lld), miss %.2f%%, %s regrown",
             (long long)pd.chunk_get, (long long)pd.chunk_regrow, (long long)pd.chunk_new,
             miss_percent(pd.chunk_regrow, pd.chunk_get), a);
    if (rekeys > 0) {
        log_line("  rekeys: %lld", rekeys);
    }
    if (cycles > 0) {
        log_line("  blob cycles: %lld", cycles);
    }
    for (int i = 0; i < cfg->workers; i++) {
        if (r->workers[i].failed) {
            log_line("  ERROR: %s", r->workers[i].error);
        }
    }
    if (pass) {
        log_line("  verdict: PASS");
        return 0;
    }
    log_line("  verdict: FAIL (errors=%d)", errors);
    return 1;
}
