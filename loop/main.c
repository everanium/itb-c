/*
 * Long-run stress harness. The loop utility holds one Pipeline handle
 * per exercised cipher surface for minutes, hammers it with
 * concurrent encrypt → decrypt → compare round-trips from N worker
 * threads, rotates the outer masters and reopens the handle from its
 * session blob on a schedule, and reports whether the process
 * survived with every byte intact. It is the C binding's counterpart
 * of the Go harness under tools/loop: the same flags, the same round
 * structure, the same summary in both renderings.
 *
 * The default shape is full production: the Streaming AEAD profile
 * with parallax on, wrapper on, hmac-blake3 MAC, Areion-SoEM-512
 * inner hash, 1024-bit keys, and the compile-in 512-bit nonce width,
 * driven through a stream session by three workers for five minutes
 * on 16 MiB plaintexts. Every worker owns a distinct CSPRNG-generated
 * plaintext held for the whole run, so any cross-call state leakage
 * inside the Pipeline surfaces as a data mismatch between workers
 * rather than cancelling out.
 *
 * A failure is one of two things. A cipher, rekey or load call that
 * returns a non-OK status is a worker error: the run stops, the
 * summary lists it, the verdict is FAIL and the exit code 1. A
 * round-trip that returns without error but with different bytes is
 * a data mismatch: the process terminates on the spot with exit
 * code 3, printing the worker, the iteration and the first differing
 * offset, and no summary — the state that produced the wrong bytes
 * is the evidence. A crash inside the shared library or the host
 * runtime has no exit code of its own here; surfacing it is what the
 * utility is for.
 *
 * Usage:
 *
 *   ./loop --duration 5m --goroutines 3 --shape stream --hash areion512 \
 *          --mac hmac-blake3 --payload-size 16MB --memlimit auto \
 *          --parallax on --wrapper on
 *
 * Ctrl-C triggers a graceful shutdown: in-flight iterations complete,
 * then the partial summary prints.
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "loop.h"

/* Profiles the shape-based pair is built against when --profile is
 * empty. */
#define DEFAULT_STREAM_PROFILE "streaming-aead-triple-mac-v1"
#define DEFAULT_MESSAGE_PROFILE "singlemsg-triple-mac-v1"

/* ------------------------------------------------------------------ */
/* Logging                                                             */
/* ------------------------------------------------------------------ */

/* Prints one prefixed status line to stdout. */
void log_line(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fputs("[loop] ", stdout);
    vprintf(fmt, ap);
    putchar('\n');
    va_end(ap);
    fflush(stdout);
}

const char *on_off(bool b)
{
    return b ? "on" : "off";
}

/* Renders an encoder policy env value for the summary: the raw string
 * when set, "default" when the shipped ladder applies. */
const char *policy_label(const char *env)
{
    if (env == NULL) {
        return "default";
    }
    while (*env == ' ' || *env == '\t') {
        env++;
    }
    return *env != '\0' ? env : "default";
}

/* ------------------------------------------------------------------ */
/* Flags                                                               */
/* ------------------------------------------------------------------ */

enum flag_kind { FLAG_INT, FLAG_INT64, FLAG_UINT64, FLAG_STRING, FLAG_BOOL };

/* One command-line flag: its name, its help text, and where the raw
 * value lands. Values are validated after the whole line is parsed. */
struct flag {
    const char *name;
    const char *type_label;
    enum flag_kind kind;
    void *dst;
    const char *help;
};

/* The raw flag values before validation. String defaults are
 * literals; strings given on the command line point into argv. */
struct raw_flags {
    int barrier_fill;
    int64_t blob_cycle_every;
    int blob_mode;
    const char *chunk_size;
    const char *drbg;
    const char *duration;
    int gogc;
    int gomaxprocs;
    int goroutines;
    const char *hash;
    int64_t iterations;
    bool json_output;
    int key_bits;
    const char *mac;
    const char *memlimit;
    const char *memprofile;
    int nonce_bits;
    const char *parallax;
    const char *payload_mode;
    const char *payload_size;
    const char *profile;
    int64_t rekey_every;
    uint64_t seed;
    const char *shape;
    const char *wrapper;
};

/* The flag table, in alphabetical order (the order the usage prints). */
static struct flag *flag_table(struct raw_flags *f, size_t *count)
{
    static struct flag table[25];
    static const struct flag proto[25] = {
        { "barrier-fill", "int", FLAG_INT, NULL,
          "DRBG barrier fill margin: 1 | 2 | 4 | 8 | 16 | 32; 0 = profile default (1)" },
        { "blob-cycle-every", "int", FLAG_INT64, NULL,
          "reopen each pipeline from its session blob every N iterations per worker; 0 = never" },
        { "blob-mode", "int", FLAG_INT, NULL,
          "container floor sizing mode: 1 (per-region, default) | 2 (per-container)" },
        { "chunk-size", "string", FLAG_STRING, NULL,
          "streaming chunk-size budget (e.g. 4MB); 0 = profile default; inert for pure message shape" },
        { "drbg", "string", FLAG_STRING, NULL,
          "DRBG fill primitive name (see itb3 drbgs); empty = profile default (auto tier)" },
        { "duration", "duration", FLAG_STRING, NULL,
          "run duration (Go format: 30s / 5m / 1h); ignored when --iterations > 0" },
        { "gogc", "int", FLAG_INT, NULL,
          "GC trigger percentage; 0 = leave the runtime default" },
        { "gomaxprocs", "int", FLAG_INT, NULL,
          "Go runtime GOMAXPROCS override; 0 = inherit from the environment" },
        { "goroutines", "int", FLAG_INT, NULL,
          "concurrent workers (1..10); on runtimes without parallelism values above 1 are clamped to 1" },
        { "hash", "string", FLAG_STRING, NULL,
          "inner ITB hash primitive name" },
        { "iterations", "int", FLAG_INT64, NULL,
          "fixed per-worker iteration count; 0 = duration-based" },
        { "json-output", "", FLAG_BOOL, NULL,
          "print the final summary as one compact JSON object instead of log lines" },
        { "key-bits", "int", FLAG_INT, NULL,
          "per-seed key width in bits: 512 | 1024 | 2048; 0 = profile default (1024)" },
        { "mac", "string", FLAG_STRING, NULL,
          "MAC primitive name" },
        { "memlimit", "string", FLAG_STRING, NULL,
          "Go heap soft limit: auto (1GiB when goroutines <= 3, else 256MiB, applied only when the runtime has no limit) or a size (e.g. 512MB)" },
        { "memprofile", "string", FLAG_STRING, NULL,
          "write a Go runtime heap profile (pprof) to this path at the end of the run; empty = none" },
        { "nonce-bits", "int", FLAG_INT, NULL,
          "on-wire nonce width in bits: 128 | 256 | 512; 0 = profile default (512)" },
        { "parallax", "string", FLAG_STRING, NULL,
          "parallax layer: on | off" },
        { "payload-mode", "string", FLAG_STRING, NULL,
          "plaintext content: fixed | rotating | pattern-zero | pattern-ff | pattern-ascii" },
        { "payload-size", "string", FLAG_STRING, NULL,
          "per-iteration plaintext size (e.g. 1MB / 16MB / 64MB)" },
        { "profile", "string", FLAG_STRING, NULL,
          "exercise this single registered triple profile (overrides --shape with the profile's surface); empty = shape-based profile pair" },
        { "rekey-every", "int", FLAG_INT64, NULL,
          "rotate the parallax + wrapper masters via Rekey every N iterations per worker; 0 = never" },
        { "seed", "uint", FLAG_UINT64, NULL,
          "deterministic plaintext RNG seed for bug reproduction, NOT for security testing (pipeline keys stay CSPRNG-drawn); 0 = crypto/rand plaintexts" },
        { "shape", "string", FLAG_STRING, NULL,
          "cipher surface to exercise: stream | message | stream_one_shot | both" },
        { "wrapper", "string", FLAG_STRING, NULL,
          "wrapper layer: on | off" },
    };
    void *dsts[25] = {
        &f->barrier_fill, &f->blob_cycle_every, &f->blob_mode, &f->chunk_size, &f->drbg, &f->duration,
        &f->gogc, &f->gomaxprocs, &f->goroutines, &f->hash, &f->iterations,
        &f->json_output, &f->key_bits, &f->mac, &f->memlimit, &f->memprofile,
        &f->nonce_bits, &f->parallax, &f->payload_mode, &f->payload_size,
        &f->profile, &f->rekey_every, &f->seed, &f->shape, &f->wrapper,
    };
    for (size_t i = 0; i < 25; i++) {
        table[i] = proto[i];
        table[i].dst = dsts[i];
    }
    *count = 25;
    return table;
}

static void usage(const struct flag *table, size_t count, const struct raw_flags *defaults)
{
    fprintf(stderr, "Usage of loop:\n");
    for (size_t i = 0; i < count; i++) {
        const struct flag *fl = &table[i];
        fprintf(stderr, "  -%s%s%s\n", fl->name, fl->type_label[0] ? " " : "", fl->type_label);
        fprintf(stderr, "    \t%s", fl->help);
        /* C-specific. The default-value suffix is composed by hand;
         * a flag library that appends its own renders it itself. */
        switch (fl->kind) {
        case FLAG_INT: {
            int v = *(const int *)((const char *)defaults + ((const char *)fl->dst - (const char *)defaults));
            if (v != 0) {
                fprintf(stderr, " (default %d)", v);
            }
            break;
        }
        case FLAG_STRING: {
            const char *v = *(const char *const *)((const char *)defaults + ((const char *)fl->dst - (const char *)defaults));
            if (v != NULL && v[0] != '\0') {
                fprintf(stderr, " (default \"%s\")", v);
            }
            break;
        }
        default:
            break;
        }
        fputc('\n', stderr);
    }
}

/* Parses one value into its flag slot; -1 on a malformed value. */
static int assign_flag(const struct flag *fl, const char *value)
{
    char *end = NULL;
    errno = 0;
    switch (fl->kind) {
    case FLAG_INT: {
        long v = strtol(value, &end, 10);
        if (*value == '\0' || *end != '\0' || errno != 0 || v > 2147483647L || v < -2147483647L) {
            return -1;
        }
        *(int *)fl->dst = (int)v;
        return 0;
    }
    case FLAG_INT64: {
        long long v = strtoll(value, &end, 10);
        if (*value == '\0' || *end != '\0' || errno != 0) {
            return -1;
        }
        *(int64_t *)fl->dst = (int64_t)v;
        return 0;
    }
    case FLAG_UINT64: {
        if (*value == '-') {
            return -1;
        }
        unsigned long long v = strtoull(value, &end, 10);
        if (*value == '\0' || *end != '\0' || errno != 0) {
            return -1;
        }
        *(uint64_t *)fl->dst = (uint64_t)v;
        return 0;
    }
    case FLAG_STRING:
        *(const char **)fl->dst = value;
        return 0;
    case FLAG_BOOL:
        if (strcmp(value, "true") == 0) {
            *(bool *)fl->dst = true;
        } else if (strcmp(value, "false") == 0) {
            *(bool *)fl->dst = false;
        } else {
            return -1;
        }
        return 0;
    }
    return -1;
}

/* Parses argv into the raw flag values. Accepts -name value,
 * --name value, -name=value and --name=value; a boolean flag takes
 * no value unless given as -name=true / -name=false. Returns 0, 1
 * for -h / --help (usage printed), or -1 after printing the error. */
static int parse_argv(int argc, char **argv, struct raw_flags *f)
{
    size_t count = 0;
    struct flag *table = flag_table(f, &count);
    struct raw_flags defaults = *f;
    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (arg[0] != '-' || arg[1] == '\0') {
            fprintf(stderr, "loop: unexpected positional arguments: [%s]\n", arg);
            return -1;
        }
        const char *name = arg + (arg[1] == '-' ? 2 : 1);
        if (strcmp(name, "h") == 0 || strcmp(name, "help") == 0) {
            usage(table, count, &defaults);
            return 1;
        }
        const char *eq = strchr(name, '=');
        size_t name_len = eq != NULL ? (size_t)(eq - name) : strlen(name);
        const struct flag *fl = NULL;
        for (size_t k = 0; k < count; k++) {
            if (strlen(table[k].name) == name_len && strncmp(table[k].name, name, name_len) == 0) {
                fl = &table[k];
                break;
            }
        }
        if (fl == NULL) {
            fprintf(stderr, "loop: flag provided but not defined: -%.*s\n", (int)name_len, name);
            usage(table, count, &defaults);
            return -1;
        }
        const char *value = NULL;
        if (eq != NULL) {
            value = eq + 1;
        } else if (fl->kind == FLAG_BOOL) {
            value = "true";
        } else if (i + 1 < argc) {
            value = argv[++i];
        } else {
            fprintf(stderr, "loop: flag needs an argument: -%s\n", fl->name);
            return -1;
        }
        if (assign_flag(fl, value) != 0) {
            fprintf(stderr, "loop: invalid value \"%s\" for flag -%s\n", value, fl->name);
            return -1;
        }
    }
    return 0;
}

/* Maps "on" / "off" to a bool; -1 otherwise. */
static int parse_on_off(const char *v, bool *out)
{
    if (strcmp(v, "on") == 0) {
        *out = true;
        return 0;
    }
    if (strcmp(v, "off") == 0) {
        *out = false;
        return 0;
    }
    return -1;
}

/* Whether name is in the JSON array of strings the binding returns
 * for the shipped hash registry. Names are restricted to [a-z0-9-],
 * so a quoted run is one complete name. */
static int hash_registered(const char *name)
{
    char *json = NULL;
    if (itb_hash_names(&json) != ITB_STATUS_OK) {
        return 0;
    }
    char quoted[128];
    (void)snprintf(quoted, sizeof(quoted), "\"%s\"", name);
    int found = strstr(json, quoted) != NULL;
    itb_string_free(json);
    return found;
}

/* The primitive supplied for the parallax palette and the outer
 * cipher when a profile leaves them unnamed. AES-CMAC is PRF-grade,
 * so it is sound outside the Interlocked Barrier, and it is the
 * closest relative of the AES-based inner primitive whose profiles
 * need this fill. */
#define KEYSTREAM_FILL_CIPHER "aescmac"

/* Folds a keystream primitive into opts for any layer the named
 * profile leaves unfilled but the operator asked for.
 *
 * A profile built around a primitive that is safe only inside the
 * Interlocked Barrier ships with no parallax palette and no outer
 * cipher: both layers run outside the barrier, where that primitive
 * would stand bare, so the recipe leaves them unnamed rather than
 * naming a primitive that must not key them. Engaging either layer
 * therefore needs a keystream-capable primitive supplied from
 * outside the recipe; without it construction fails on a palette
 * below its minimum or an unnamed outer cipher, and the primitive
 * that most deserves stressing becomes the one that cannot be
 * stressed with those layers engaged.
 *
 * Overrides fold into the resolved record the blob carries, so the
 * receiver rebuilds the same shape from the blob alone.
 *
 * C-specific. The record is read as JSON text and the two keys are
 * probed by substring: an absent "palette" or "outer" key is the
 * unfilled state, since the encoder omits both when unset.
 *
 * Returns 1 when a layer was filled, 0 when none needed it, -1 on a
 * lookup failure (message already printed). */
static int fill_keystream_layers(const char *name, itb_opts *opts,
                                 int want_parallax, int want_wrapper)
{
    char *json = NULL;
    if (itb_lookup(name, &json) != ITB_STATUS_OK) {
        fprintf(stderr, "loop: --profile \"%s\" is not a registered triple profile\n", name);
        return -1;
    }
    int filled = 0;
    if (want_parallax && strstr(json, "\"palette\":") == NULL) {
        (void)itb_opts_set(opts, "parallaxPalette",
                           KEYSTREAM_FILL_CIPHER "," KEYSTREAM_FILL_CIPHER "," KEYSTREAM_FILL_CIPHER);
        if (strstr(json, "\"segment\":") == NULL) {
            /* A recipe that never carried a palette never carried a
             * segment size either, and the schedule rejects zero. */
            (void)itb_opts_set(opts, "parallaxSegmentSize", "4093");
        }
        filled = 1;
    }
    if (want_wrapper && strstr(json, "\"outer\":") == NULL) {
        (void)itb_opts_set(opts, "outerCipher", KEYSTREAM_FILL_CIPHER);
        filled = 1;
    }
    itb_string_free(json);
    return filled;
}

/* Resolves a registered profile to the shape family its record's
 * mode exposes by reading the record through the binding's lookup:
 * a mode beginning with "streaming" exposes the stream surfaces, one
 * beginning with "singlemsg" the message surface, "blob-only" none.
 * Prints the validation message and returns -1 on rejection. */
static int profile_surface(const char *name, enum shape *surface)
{
    char *json = NULL;
    if (itb_lookup(name, &json) != ITB_STATUS_OK) {
        fprintf(stderr, "loop: --profile \"%s\" is not a registered triple profile\n", name);
        return -1;
    }
    const char *mode = strstr(json, "\"mode\":\"");
    int rc = -1;
    if (mode != NULL) {
        mode += strlen("\"mode\":\"");
        if (strncmp(mode, "streaming", 9) == 0) {
            *surface = SHAPE_STREAM;
            rc = 0;
        } else if (strncmp(mode, "singlemsg", 9) == 0) {
            *surface = SHAPE_MESSAGE;
            rc = 0;
        }
    }
    itb_string_free(json);
    if (rc != 0) {
        fprintf(stderr, "loop: --profile \"%s\" carries no cipher surface (blob-only mode)\n", name);
    }
    return rc;
}

/* Applies a --profile's surface to the requested shape: a
 * message-surface profile forces message; a stream-surface profile
 * keeps stream or stream_one_shot as requested and turns message or
 * both into stream. */
static enum shape narrow_shape(enum shape requested, enum shape surface)
{
    if (surface == SHAPE_MESSAGE) {
        return SHAPE_MESSAGE;
    }
    return requested == SHAPE_STREAM_ONE_SHOT ? SHAPE_STREAM_ONE_SHOT : SHAPE_STREAM;
}

/* Builds the resolved config from argv. Returns 0, 1 for help, or
 * -1 after printing "loop: <message>" for the first failing rule. */
static int parse_flags(int argc, char **argv, struct config *cfg)
{
    struct raw_flags f = {
        .barrier_fill = 0, .blob_cycle_every = 0, .blob_mode = 1, .chunk_size = "0",
        .drbg = "", .duration = "5m", .gogc = 0, .gomaxprocs = 0, .goroutines = 3,
        .hash = "areion512", .iterations = 0, .json_output = false,
        .key_bits = 0, .mac = "hmac-blake3", .memlimit = "auto",
        .memprofile = "", .nonce_bits = 0, .parallax = "on",
        .payload_mode = "fixed", .payload_size = "16MB", .profile = "",
        .rekey_every = 0, .seed = 0, .shape = "stream", .wrapper = "on",
    };
    int rc = parse_argv(argc, argv, &f);
    if (rc != 0) {
        return rc;
    }

    memset(cfg, 0, sizeof(*cfg));
    if (parse_duration(f.duration, &cfg->duration_ns) != 0 || cfg->duration_ns <= 0) {
        fprintf(stderr, "loop: --duration must be positive, got %s\n", f.duration);
        return -1;
    }
    cfg->iterations = f.iterations;
    if (cfg->iterations < 0) {
        fprintf(stderr, "loop: --iterations must be >= 0, got %lld\n", (long long)cfg->iterations);
        return -1;
    }
    if (f.goroutines < 1 || f.goroutines > LOOP_MAX_WORKERS) {
        fprintf(stderr, "loop: --goroutines must be in 1..%d, got %d\n", LOOP_MAX_WORKERS, f.goroutines);
        return -1;
    }
    /* Concurrency mode. This binding runs shared-handle: POSIX
     * threads call into one Pipeline handle concurrently, which the
     * shared library permits after construction, so --goroutines is
     * the thread count verbatim, never clamped. */
    cfg->workers_requested = f.goroutines;
    cfg->workers = f.goroutines;
    if (parse_shape(f.shape, &cfg->shape) != 0) {
        fprintf(stderr, "loop: --shape must be stream | message | stream_one_shot | both, got \"%s\"\n", f.shape);
        return -1;
    }
    if (!hash_registered(f.hash)) {
        fprintf(stderr, "loop: --hash \"%s\" is not a registered hash primitive\n", f.hash);
        return -1;
    }
    cfg->hash = f.hash;
    cfg->mac = f.mac; /* validated by Init: the C ABI enumerates no MAC names */
    if (parse_size(f.payload_size, &cfg->payload) != 0) {
        fprintf(stderr, "loop: --payload-size: invalid size \"%s\"\n", f.payload_size);
        return -1;
    }
    if (cfg->payload < 1) {
        fprintf(stderr, "loop: --payload-size must be at least 1 byte\n");
        return -1;
    }
    if (strcmp(f.memlimit, "auto") == 0) {
        cfg->memlimit_auto = true;
        cfg->memlimit = cfg->workers <= 3 ? ((int64_t)1 << 30) : ((int64_t)256 << 20);
    } else if (parse_size(f.memlimit, &cfg->memlimit) != 0) {
        fprintf(stderr, "loop: --memlimit: invalid size \"%s\"\n", f.memlimit);
        return -1;
    }
    cfg->gogc = f.gogc;
    if (cfg->gogc < 0) {
        fprintf(stderr, "loop: --gogc must be >= 0, got %d\n", cfg->gogc);
        return -1;
    }
    if (parse_on_off(f.parallax, &cfg->parallax) != 0) {
        fprintf(stderr, "loop: --parallax must be on | off, got \"%s\"\n", f.parallax);
        return -1;
    }
    if (parse_on_off(f.wrapper, &cfg->wrapper) != 0) {
        fprintf(stderr, "loop: --wrapper must be on | off, got \"%s\"\n", f.wrapper);
        return -1;
    }
    cfg->profile = f.profile;
    if (cfg->profile[0] != '\0') {
        enum shape surface;
        if (profile_surface(cfg->profile, &surface) != 0) {
            return -1;
        }
        cfg->shape = narrow_shape(cfg->shape, surface);
    }
    cfg->key_bits = f.key_bits;
    switch (cfg->key_bits) {
    case 0: case 512: case 1024: case 2048:
        break;
    default:
        fprintf(stderr, "loop: --key-bits must be 512 | 1024 | 2048 (or 0 = profile default), got %d\n", cfg->key_bits);
        return -1;
    }
    cfg->nonce_bits = f.nonce_bits;
    switch (cfg->nonce_bits) {
    case 0: case 128: case 256: case 512:
        break;
    default:
        fprintf(stderr, "loop: --nonce-bits must be 128 | 256 | 512 (or 0 = profile default), got %d\n", cfg->nonce_bits);
        return -1;
    }
    cfg->blob_mode = f.blob_mode;
    switch (cfg->blob_mode) {
    case 1: case 2:
        break;
    default:
        fprintf(stderr, "loop: --blob-mode must be 1 (per-region) | 2 (per-container), got %d\n", cfg->blob_mode);
        return -1;
    }
    cfg->barrier_fill = f.barrier_fill;
    switch (cfg->barrier_fill) {
    case 0: case 1: case 2: case 4: case 8: case 16: case 32:
        break;
    default:
        fprintf(stderr, "loop: --barrier-fill must be 1 | 2 | 4 | 8 | 16 | 32 (or 0 = profile default), got %d\n", cfg->barrier_fill);
        return -1;
    }
    cfg->drbg = f.drbg; /* validated by Init: the C ABI enumerates no DRBG names */
    if (parse_size(f.chunk_size, &cfg->chunk_size) != 0) {
        fprintf(stderr, "loop: --chunk-size: invalid size \"%s\"\n", f.chunk_size);
        return -1;
    }
    cfg->gomaxprocs = f.gomaxprocs;
    if (cfg->gomaxprocs < 0) {
        fprintf(stderr, "loop: --gomaxprocs must be > 0 when specified, got %d\n", cfg->gomaxprocs);
        return -1;
    }
    cfg->rekey_every = f.rekey_every;
    if (cfg->rekey_every < 0) {
        fprintf(stderr, "loop: --rekey-every must be >= 0, got %lld\n", (long long)cfg->rekey_every);
        return -1;
    }
    cfg->blob_cycle_every = f.blob_cycle_every;
    if (cfg->blob_cycle_every < 0) {
        fprintf(stderr, "loop: --blob-cycle-every must be >= 0, got %lld\n", (long long)cfg->blob_cycle_every);
        return -1;
    }
    if (parse_payload_mode(f.payload_mode, &cfg->payload_mode) != 0) {
        fprintf(stderr, "loop: --payload-mode must be fixed | rotating | pattern-zero | pattern-ff | pattern-ascii, got \"%s\"\n", f.payload_mode);
        return -1;
    }
    cfg->seed = f.seed;
    cfg->json_output = f.json_output;
    cfg->memprofile = f.memprofile;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Signals                                                             */
/* ------------------------------------------------------------------ */

static volatile sig_atomic_t signal_seen = 0;

static void on_signal(int sig)
{
    (void)sig;
    signal_seen = 1;
}

/* Graceful stop. SIGINT / SIGTERM set a flag the main thread polls
 * while it waits for the workers; it turns the flag into the stop
 * request every worker checks before starting an iteration, so a
 * signal interrupts nothing mid-call — the in-flight encrypt /
 * decrypt / compare completes, the worker returns, and the partial
 * summary prints with the verdict the completed iterations earned. */
static void install_signals(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

/* ------------------------------------------------------------------ */
/* Pipelines                                                           */
/* ------------------------------------------------------------------ */

/* Integer value of key in a profile JSON record; 0 when absent. */
static long long record_int(const char *json, const char *key)
{
    char needle[64];
    (void)snprintf(needle, sizeof(needle), "\"%s\":", key);
    const char *p = strstr(json, needle);
    return p != NULL ? strtoll(p + strlen(needle), NULL, 10) : 0;
}

/* String value of key in a profile JSON record, or "-" when absent
 * or empty. Profile record strings are restricted to [a-z0-9-], so a
 * quoted run is one complete value. */
static void record_str(const char *json, const char *key, char *out, size_t cap)
{
    char needle[64];
    (void)snprintf(needle, sizeof(needle), "\"%s\":\"", key);
    const char *p = strstr(json, needle);
    if (p == NULL) {
        (void)snprintf(out, cap, "-");
        return;
    }
    p += strlen(needle);
    const char *end = strchr(p, '"');
    if (end == NULL || end == p) {
        (void)snprintf(out, cap, "-");
        return;
    }
    (void)snprintf(out, cap, "%.*s", (int)(end - p), p);
}

/* Boolean value of key in a profile JSON record; false when absent. */
static int record_bool(const char *json, const char *key)
{
    char needle[64];
    (void)snprintf(needle, sizeof(needle), "\"%s\":true", key);
    return strstr(json, needle) != NULL;
}

/* Prints the construction line with the recipe read back from the
 * blob the Pipeline handed out, not echoed from the flags: every
 * construction override is proven to have reached the library by the
 * value the receiver would see. Record values that are empty (a No
 * MAC profile's MAC, a mixed profile's single hash) print as "-". */
static void log_pipeline_initialised(const char *profile, const uint8_t *blob, size_t blob_len)
{
    char *json = NULL;
    if (itb_inspect(blob, blob_len, &json) != ITB_STATUS_OK) {
        log_line("pipeline initialised: profile=%s blob=%zu bytes (inspect: %s)", profile, blob_len,
                 itb_last_error());
        return;
    }
    char hash[64];
    char mac[64];
    char drbg[64];
    record_str(json, "hash", hash, sizeof(hash));
    record_str(json, "mac", mac, sizeof(mac));
    record_str(json, "drbg", drbg, sizeof(drbg));
    long long container_mode = record_int(json, "container_mode");
    char line[1024];
    int n = snprintf(line, sizeof(line),
                     "pipeline initialised: profile=%s blob=%zu bytes hash=%s key-bits=%lld nonce-bits=%lld barrier-fill=%lld chunk-size=%lld mac=%s parallax=%s wrapper=%s",
                     profile, blob_len, hash, record_int(json, "keybits"), record_int(json, "nonce_bits"),
                     record_int(json, "barrier_fill"), record_int(json, "chunk"), mac,
                     on_off(record_bool(json, "parallax") != 0), on_off(record_bool(json, "wrapper") != 0));
    if (n > 0 && (size_t)n < sizeof(line) && container_mode == 2) {
        n += snprintf(line + n, sizeof(line) - (size_t)n, " container-mode=%lld", container_mode);
    }
    if (n > 0 && (size_t)n < sizeof(line) && strcmp(drbg, "-") != 0) {
        n += snprintf(line + n, sizeof(line) - (size_t)n, " drbg=%s", drbg);
    }
    log_line("%s", line);
    itb_string_free(json);
}

/* Offset of the first occurrence of needle in hay, or hay_len when
 * absent. The blob is JSON text handed over without a terminator, so
 * the search is bounded by length rather than by a NUL. */
static size_t find_bytes(const uint8_t *hay, size_t hay_len, const char *needle, size_t needle_len)
{
    for (size_t i = 0; i + needle_len <= hay_len; i++) {
        if (memcmp(hay + i, needle, needle_len) == 0) {
            return i;
        }
    }
    return hay_len;
}

/* Sets the inner blob's "mode" field of a wrap-layer session blob to
 * target_mode (1 = per-region, 2 = per-container) in place. The wrap
 * layer's profile record carries its own "mode" (a string), so the
 * search starts at the inner blob ("ib"); both shipped modes are one
 * digit wide, so the blob length does not change and the key material
 * in blob is never copied. Returns -1 when the inner blob or its mode
 * field is not found. */
static int edit_inner_blob_mode(uint8_t *blob, size_t blob_len, int target_mode)
{
    static const char ib_key[] = "\"ib\":{";
    static const char mode_key[] = "\"mode\":";
    size_t ib = find_bytes(blob, blob_len, ib_key, sizeof(ib_key) - 1);
    if (ib == blob_len) {
        return -1;
    }
    size_t off = ib + sizeof(ib_key) - 1;
    size_t mode = find_bytes(blob + off, blob_len - off, mode_key, sizeof(mode_key) - 1);
    if (mode == blob_len - off) {
        return -1;
    }
    size_t at = off + mode + sizeof(mode_key) - 1;
    if (at + 1 >= blob_len || blob[at] < '1' || blob[at] > '2' || (blob[at + 1] >= '0' && blob[at + 1] <= '9')) {
        return -1;
    }
    blob[at] = (uint8_t)('0' + target_mode);
    return 0;
}

/* Constructs one Pipeline against profile with every flag-carried
 * override in the opts string (zero values included — the shared
 * library treats zero as "profile default"), then obtains the Init
 * blob once through save: the binding's init entry does not hand the
 * blob back, and the bytes are the ones Init produced. Later blob
 * reopens use the retained blob; save is never called again. */
static int build_pipeline(const struct config *cfg, const char *profile,
                          itb_pipeline **pipe, uint8_t **blob, size_t *blob_len)
{
    itb_opts *opts = itb_opts_new();
    if (opts == NULL) {
        fprintf(stderr, "loop: out of memory\n");
        return -1;
    }
    char num[32];
    (void)itb_opts_set(opts, "innerHash", cfg->hash);
    (void)itb_opts_set(opts, "macName", cfg->mac);
    (void)itb_opts_set(opts, "withParallax", cfg->parallax ? "true" : "false");
    (void)itb_opts_set(opts, "withWrapper", cfg->wrapper ? "true" : "false");
    (void)snprintf(num, sizeof(num), "%d", cfg->key_bits);
    (void)itb_opts_set(opts, "keyBits", num);
    (void)snprintf(num, sizeof(num), "%d", cfg->nonce_bits);
    (void)itb_opts_set(opts, "nonceBits", num);
    (void)snprintf(num, sizeof(num), "%d", cfg->barrier_fill);
    (void)itb_opts_set(opts, "barrierFill", num);
    (void)itb_opts_set(opts, "drbg", cfg->drbg);
    (void)snprintf(num, sizeof(num), "%lld", (long long)cfg->chunk_size);
    (void)itb_opts_set(opts, "chunkSize", num);
    if (cfg->profile != NULL && cfg->profile[0] != '\0') {
        int filled = fill_keystream_layers(cfg->profile, opts, cfg->parallax, cfg->wrapper);
        if (filled < 0) {
            itb_opts_free(opts);
            return -1;
        }
        if (filled > 0) {
            fprintf(stderr, "loop: %s leaves the requested keystream layers unnamed; %s supplied for them\n",
                    cfg->profile, KEYSTREAM_FILL_CIPHER);
        }
    }

    itb_status st = itb_pipeline_init(profile, opts, pipe);
    itb_opts_free(opts);
    if (st != ITB_STATUS_OK) {
        fprintf(stderr, "loop: Init(%s): status %d: %s\n", profile, (int)st, itb_last_error());
        return -1;
    }
    st = itb_pipeline_save(*pipe, blob, blob_len);
    if (st != ITB_STATUS_OK) {
        fprintf(stderr, "loop: Save(%s): status %d: %s\n", profile, (int)st, itb_last_error());
        itb_pipeline_free(*pipe);
        *pipe = NULL;
        return -1;
    }
    if (cfg->blob_mode == 2) {
        /* The sizing mode is not an Opts knob: the Init blob is edited
         * and the pipeline reopened from it, so the retained blob (the
         * one blob-cycle reopens from) carries the edited mode. */
        if (edit_inner_blob_mode(*blob, *blob_len, 2) != 0) {
            fprintf(stderr, "loop: rewrite blob mode: inner blob mode field not found\n");
            itb_pipeline_free(*pipe);
            *pipe = NULL;
            itb_bytes_free(*blob);
            *blob = NULL;
            return -1;
        }
        itb_pipeline_free(*pipe);
        *pipe = NULL;
        st = itb_pipeline_load(*blob, *blob_len, NULL, 0, NULL, 0, pipe);
        if (st != ITB_STATUS_OK) {
            fprintf(stderr, "loop: reload Mode 2 blob: status %d: %s\n", (int)st, itb_last_error());
            itb_bytes_free(*blob);
            *blob = NULL;
            return -1;
        }
    }
    log_pipeline_initialised(profile, *blob, *blob_len);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Run                                                                 */
/* ------------------------------------------------------------------ */

static int run(int argc, char **argv)
{
    static struct run_state r;
    struct config *cfg = &r.cfg;
    int rc = parse_flags(argc, argv, cfg);
    if (rc == 1) {
        return 0;
    }
    if (rc != 0) {
        return 2;
    }

    /* Runtime shaping. A long run under allocation churn grows the
     * Go heap inside the shared library without bound unless a soft
     * limit paces the collector, so a limit is always in force: an
     * explicit --memlimit is set as given, and auto caps the heap
     * only when the runtime reports no limit at all (a limit already
     * installed from the environment is left standing). The GC
     * percentage and GOMAXPROCS are set only when their flag is
     * non-zero — a zero flag skips the setter rather than calling it
     * with zero, because zero is a real value to the GC-percent
     * setter, and a call would clobber whatever the environment
     * installed. All of it lands before any Pipeline exists so the
     * baselines are taken under the shaped runtime. */
    if (cfg->memlimit_auto) {
        if (itb_set_memory_limit(-1) == INT64_MAX) {
            (void)itb_set_memory_limit(cfg->memlimit);
        }
    } else {
        (void)itb_set_memory_limit(cfg->memlimit);
    }
    cfg->memlimit = itb_set_memory_limit(-1);
    if (cfg->gogc > 0) {
        (void)itb_set_gc_percent(cfg->gogc);
    }
    if (cfg->gomaxprocs > 0) {
        (void)itb_set_gomaxprocs(cfg->gomaxprocs);
    }

    char a[32], b[32], c[32];
    human_duration(cfg->duration_ns, a, sizeof(a));
    human_bytes(cfg->payload, b, sizeof(b));
    human_bytes(cfg->memlimit, c, sizeof(c));
    log_line("start: duration=%s iterations=%lld goroutines=%d workers=%d concurrency=%s shape=%s hash=%s mac=%s payload=%s memlimit=%s parallax=%s wrapper=%s",
             a, (long long)cfg->iterations, cfg->workers_requested, cfg->workers, LOOP_CONCURRENCY,
             shape_name(cfg->shape), cfg->hash, cfg->mac, b, c, on_off(cfg->parallax), on_off(cfg->wrapper));
    human_bytes(cfg->chunk_size, a, sizeof(a));
    {
        char overrides[1024];
        int n = snprintf(overrides, sizeof(overrides),
                         "overrides: profile=\"%s\" key-bits=%d nonce-bits=%d chunk-size=%s barrier-fill=%d gomaxprocs=%d rekey-every=%lld blob-cycle-every=%lld payload-mode=%s seed=%llu json-output=%s",
                         cfg->profile, cfg->key_bits, cfg->nonce_bits, a, cfg->barrier_fill, cfg->gomaxprocs,
                         (long long)cfg->rekey_every, (long long)cfg->blob_cycle_every,
                         payload_mode_name(cfg->payload_mode), (unsigned long long)cfg->seed,
                         cfg->json_output ? "true" : "false");
        if (n > 0 && (size_t)n < sizeof(overrides) && cfg->blob_mode != 1) {
            n += snprintf(overrides + n, sizeof(overrides) - (size_t)n, " blob-mode=%d", cfg->blob_mode);
        }
        if (n > 0 && (size_t)n < sizeof(overrides) && cfg->drbg[0] != '\0') {
            n += snprintf(overrides + n, sizeof(overrides) - (size_t)n, " drbg=%s", cfg->drbg);
        }
        log_line("%s", overrides);
    }
    log_line("policy: microbatch-tiers=%s hashpool-starters=%s",
             policy_label(getenv("ITB_MICROBATCH_TIERS")), policy_label(getenv("ITB_HASHPOOL_STARTERS")));

    /* Pipeline construction — one shared handle per exercised shape.
     * stream and stream_one_shot share the streaming handle. */
    r.stream_profile = cfg->profile[0] != '\0' ? cfg->profile : DEFAULT_STREAM_PROFILE;
    r.msg_profile = cfg->profile[0] != '\0' ? cfg->profile : DEFAULT_MESSAGE_PROFILE;
    if (cfg->shape == SHAPE_STREAM || cfg->shape == SHAPE_STREAM_ONE_SHOT || cfg->shape == SHAPE_BOTH) {
        if (build_pipeline(cfg, r.stream_profile, &r.stream_pipe, &r.stream_blob, &r.stream_blob_len) != 0) {
            return 1;
        }
    }
    if (cfg->shape == SHAPE_MESSAGE || cfg->shape == SHAPE_BOTH) {
        if (build_pipeline(cfg, r.msg_profile, &r.msg_pipe, &r.msg_blob, &r.msg_blob_len) != 0) {
            return 1;
        }
    }

    /* Allocation posture. Per-worker plaintexts are allocated once and
     * held for the whole run (rotating mode refills them in place per
     * iteration); the pump accumulators live inside each worker and
     * are reused across iterations; the message and one-shot outputs
     * are allocated by the binding per call and released per
     * iteration. Under the default fixed CSPRNG mode every worker's
     * buffer is distinct, so cross-worker data crossover is
     * detectable; pattern modes trade that property for content
     * edge-case coverage. */
    for (int i = 0; i < cfg->workers; i++) {
        struct worker *w = &r.workers[i];
        w->id = i;
        w->run = &r;
        w->plaintext_len = (size_t)cfg->payload;
        w->plaintext = malloc(w->plaintext_len);
        if (w->plaintext == NULL) {
            fprintf(stderr, "loop: payload alloc: out of memory\n");
            return 1;
        }
        w->payload_mode = cfg->payload_mode;
        w->seeded = cfg->seed != 0;
        w->rng = seed_worker(cfg->seed, i);
        if (fill_payload(cfg->payload_mode, w->seeded, &w->rng, w->plaintext, w->plaintext_len) != 0) {
            fprintf(stderr, "loop: payload fill: csprng\n");
            return 1;
        }
    }

    if (pool_snapshot_alloc(&r.pool_warmup, &r.pool_len) != 0
        || pool_snapshot_alloc(&r.pool_steady, &r.pool_len) != 0) {
        fprintf(stderr, "loop: pool snapshot alloc failed\n");
        return 1;
    }

    install_signals();
    pthread_rwlock_init(&r.pipe_lock, NULL);
    pthread_mutex_init(&r.done_mu, NULL);
    pthread_cond_init(&r.done_cv, NULL);
    pthread_barrier_init(&r.warmup_done, NULL, (unsigned)cfg->workers + 1u);
    pthread_barrier_init(&r.release, NULL, (unsigned)cfg->workers + 1u);
    atomic_store(&r.stop, false);
    r.active = cfg->workers;

    /* Warmup barrier. Every worker runs one iteration and waits; the
     * clock starts only once all of them have paid their first-call
     * costs (pool warm-up, lazy kernel dispatch, page faults on the
     * payload buffers), and the RSS and pool baselines taken here
     * describe a process that has already run the whole cipher path
     * once per worker. */
    int64_t warmup_start = now_ns();
    for (int i = 0; i < cfg->workers; i++) {
        if (pthread_create(&r.workers[i].thread, NULL, worker_main, &r.workers[i]) != 0) {
            fprintf(stderr, "loop: pthread_create failed\n");
            return 1;
        }
    }
    pthread_barrier_wait(&r.warmup_done);
    read_rss(&r.rss_warmup, &r.rss_peak);
    (void)pool_snapshot_take(r.pool_warmup, r.pool_len);
    int64_t warmup_ns = now_ns() - warmup_start;
    human_duration((warmup_ns + 50000000) / 100000000 * 100000000, a, sizeof(a));
    human_bytes((int64_t)r.rss_warmup, b, sizeof(b));
    log_line("warmup: %d workers x 1 iter completed in %s (baseline rss=%s)", cfg->workers, a, b);

    /* Open the gate; the duration timer is a deadline the waiter
     * below enforces in duration mode. */
    r.start_ns = now_ns();
    r.finish_ns = r.start_ns;
    pthread_barrier_wait(&r.release);

    /* Wait for every worker, polling every 100 ms so the deadline and
     * a signal are both noticed promptly. */
    pthread_mutex_lock(&r.done_mu);
    while (r.active > 0) {
        if (signal_seen) {
            atomic_store(&r.stop, true);
        }
        if (cfg->iterations == 0 && now_ns() - r.start_ns >= cfg->duration_ns) {
            atomic_store(&r.stop, true);
        }
        struct timespec until;
        clock_gettime(CLOCK_REALTIME, &until);
        until.tv_nsec += 100000000L;
        if (until.tv_nsec >= 1000000000L) {
            until.tv_sec += 1;
            until.tv_nsec -= 1000000000L;
        }
        pthread_cond_timedwait(&r.done_cv, &r.done_mu, &until);
    }
    pthread_mutex_unlock(&r.done_mu);
    for (int i = 0; i < cfg->workers; i++) {
        pthread_join(r.workers[i].thread, NULL);
    }
    int64_t elapsed_ns = r.finish_ns - r.start_ns;
    read_rss(&r.rss_final, &r.rss_peak);
    (void)pool_snapshot_take(r.pool_steady, r.pool_len);

    if (cfg->memprofile[0] != '\0') {
        if (itb_write_heap_profile(cfg->memprofile) != ITB_STATUS_OK) {
            fprintf(stderr, "loop: memprofile: %s\n", itb_last_error());
        } else {
            log_line("memprofile: heap profile written to %s", cfg->memprofile);
        }
    }

    rc = final_summary(&r, elapsed_ns);

    /* C-specific. Release every handle and buffer so a leak checker
     * over the utility sees a clean exit; a garbage-collected language
     * lets its runtime reclaim them. */
    itb_pipeline_free(r.stream_pipe);
    itb_pipeline_free(r.msg_pipe);
    itb_bytes_free(r.stream_blob);
    itb_bytes_free(r.msg_blob);
    for (int i = 0; i < cfg->workers; i++) {
        free(r.workers[i].plaintext);
        buf_free(&r.workers[i].wire);
        buf_free(&r.workers[i].plain);
    }
    free(r.pool_warmup);
    free(r.pool_steady);
    pthread_barrier_destroy(&r.warmup_done);
    pthread_barrier_destroy(&r.release);
    pthread_cond_destroy(&r.done_cv);
    pthread_mutex_destroy(&r.done_mu);
    pthread_rwlock_destroy(&r.pipe_lock);
    return rc;
}

int main(int argc, char **argv)
{
    return run(argc, argv);
}
