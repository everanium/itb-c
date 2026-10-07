/*
 * Shared declarations of the loop stress harness: the resolved
 * configuration, the per-worker state, the run state every worker
 * shares, and the prototypes of the six units (main / ops / payload /
 * size / summary / worker).
 *
 * C-specific. A header is how C shares declarations across
 * translation units; a language with modules or a single-file build
 * folds these into the units that own them.
 */

#ifndef ITB_LOOP_H
#define ITB_LOOP_H

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "itb3.h"

/* ------------------------------------------------------------------ */
/* Vocabulary                                                          */
/* ------------------------------------------------------------------ */

/* Cipher surfaces the --shape flag selects. */
enum shape {
    SHAPE_STREAM,         /* session pump: begin / write / read / end */
    SHAPE_MESSAGE,        /* Single Message: one whole-buffer call    */
    SHAPE_STREAM_ONE_SHOT,/* stream surface, one whole-buffer call    */
    SHAPE_BOTH            /* all three, rotating by iteration number  */
};

/* Plaintext content policies the --payload-mode flag selects. */
enum payload_mode {
    PAYLOAD_FIXED,
    PAYLOAD_ROTATING,
    PAYLOAD_PATTERN_ZERO,
    PAYLOAD_PATTERN_FF,
    PAYLOAD_PATTERN_ASCII
};

/* --goroutines ceiling; the harness targets modest hosts and each
 * worker pins payload-sized buffers for the whole run. */
#define LOOP_MAX_WORKERS 10

/* The concurrency mode this binding implements, as the summary
 * reports it (shared-handle / independent-handles / single). */
#define LOOP_CONCURRENCY "shared-handle"

/* Largest slice fed to a stream session per write; the drain after
 * every write uses the same bound. */
#define LOOP_PUMP_SLICE ((size_t)1 << 20)

/* Worker-error text capacity. */
#define LOOP_ERROR_TEXT 512

/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */

/* The resolved command line. Strings point into argv (or at literals)
 * and are never freed. */
struct config {
    int64_t duration_ns;      /* run duration; ignored when iterations > 0 */
    int64_t iterations;       /* per-worker count incl. warmup; 0 = duration-based */
    int workers_requested;    /* the --goroutines value as given */
    int workers;              /* the effective worker count */
    enum shape shape;
    const char *hash;
    const char *mac;
    int64_t payload;          /* bytes per iteration */
    int64_t memlimit;         /* resolved bytes; the effective limit once shaped */
    bool memlimit_auto;       /* --memlimit auto: cap only when the runtime has no limit */
    int gogc;                 /* 0 = leave the runtime default */
    bool parallax;
    bool wrapper;

    const char *profile;      /* empty = shape-based profile pair */
    int key_bits;             /* 0 = profile default */
    int nonce_bits;           /* 0 = profile default */
    int blob_mode;            /* container floor sizing mode: 1 (per-region, default) | 2 (per-container) */
    int64_t chunk_size;       /* 0 = profile default */
    int barrier_fill;         /* 0 = profile default */
    const char *drbg;         /* DRBG fill primitive; "" = profile default (auto tier) */
    int gomaxprocs;           /* 0 = inherit from the environment */
    int64_t rekey_every;      /* per-worker iterations between rotations; 0 = never */
    int64_t blob_cycle_every; /* per-worker iterations between reopens; 0 = never */
    enum payload_mode payload_mode;
    uint64_t seed;            /* 0 = OS CSPRNG plaintexts */
    bool json_output;
    const char *memprofile;   /* empty = none */
};

/* ------------------------------------------------------------------ */
/* Growable byte buffer                                                */
/* ------------------------------------------------------------------ */

/* C-specific. An output accumulator reused across iterations so the
 * steady-state allocation profile of the pump loop stays flat; a
 * language with a growable byte container uses that instead. */
struct buf {
    uint8_t *data;
    size_t len;
    size_t cap;
};

int buf_append(struct buf *b, const uint8_t *src, size_t n);
void buf_free(struct buf *b);

/* ------------------------------------------------------------------ */
/* Worker and run state                                                */
/* ------------------------------------------------------------------ */

struct run_state;

/* One worker's private state: its plaintext, its reusable output
 * buffers, its generator, its counters, and the error it stopped on. */
struct worker {
    int id;
    struct run_state *run;
    pthread_t thread;

    uint8_t *plaintext;
    size_t plaintext_len;
    enum payload_mode payload_mode;
    bool seeded;
    uint64_t rng;             /* splitmix64 state when seeded */

    struct buf wire;          /* pump-loop wire accumulator */
    struct buf plain;         /* pump-loop round-trip accumulator */

    /* Counters read by the summary after every worker has returned. */
    atomic_int_fast64_t iters;
    atomic_int_fast64_t bytes_enc;
    atomic_int_fast64_t bytes_dec;
    atomic_int_fast64_t nanos_enc;
    atomic_int_fast64_t nanos_dec;

    bool failed;
    char error[LOOP_ERROR_TEXT];
};

/* The state every worker shares: the Pipeline handles, the retained
 * blobs, the lock that keeps iterations clear of handle mutation, the
 * stop request, the barriers, and the baselines the summary reads. */
struct run_state {
    struct config cfg;

    itb_pipeline *stream_pipe;    /* NULL unless the shape uses it */
    itb_pipeline *msg_pipe;       /* NULL unless the shape uses it */
    const char *stream_profile;
    const char *msg_profile;

    /* Handle mutation. Iterations hold the read side for their whole
     * encrypt → decrypt → compare; rekey and blob reopen take the
     * write side, so no cipher call is in flight while a handle's
     * keying changes or the handle itself is swapped, and no encrypt
     * is separated from its decrypt by either. */
    pthread_rwlock_t pipe_lock;

    /* The blob Init handed out, replaced by every rekey; the input of
     * the next blob reopen. Guarded by pipe_lock. */
    uint8_t *stream_blob;
    size_t stream_blob_len;
    uint8_t *msg_blob;
    size_t msg_blob_len;

    atomic_int_fast64_t rekeys;
    atomic_int_fast64_t blob_cycles;

    struct worker workers[LOOP_MAX_WORKERS];

    /* Warmup barrier: workers arrive at warmup_done after iteration
     * 0 and at release once main has taken the baselines. */
    pthread_barrier_t warmup_done;
    pthread_barrier_t release;

    /* Set by the duration timer, by a signal, or by a failing worker;
     * checked by every worker before it starts an iteration. */
    atomic_bool stop;

    /* Main waits on done_cv for active to reach zero; the last
     * returning worker stamps finish_ns so elapsed excludes the
     * wake-up latency of the waiter. */
    pthread_mutex_t done_mu;
    pthread_cond_t done_cv;
    int active;
    int64_t start_ns;
    int64_t finish_ns;

    /* Baselines taken after the warmup barrier and at shutdown. */
    uint64_t rss_warmup;
    uint64_t rss_peak;
    uint64_t rss_final;
    int64_t *pool_warmup;
    int64_t *pool_steady;
    size_t pool_len;
};

/* ------------------------------------------------------------------ */
/* size unit                                                           */
/* ------------------------------------------------------------------ */

int parse_size(const char *s, int64_t *out);
int parse_duration(const char *s, int64_t *out_ns);
int64_t now_ns(void);
void human_bytes(int64_t n, char *out, size_t cap);
void human_bytes_signed(int64_t n, char *out, size_t cap);
void human_rate(int64_t bytes, int64_t ns, char *out, size_t cap);
void human_duration(int64_t ns, char *out, size_t cap);
double mb_per_sec(int64_t bytes, int64_t ns);

/* ------------------------------------------------------------------ */
/* payload unit                                                        */
/* ------------------------------------------------------------------ */

const char *payload_mode_name(enum payload_mode mode);
int parse_payload_mode(const char *s, enum payload_mode *out);
uint64_t seed_worker(uint64_t seed, int worker_id);
int fill_payload(enum payload_mode mode, bool seeded, uint64_t *rng,
                 uint8_t *buf, size_t n);
int fill_random(uint8_t *buf, size_t n);

/* ------------------------------------------------------------------ */
/* ops unit                                                            */
/* ------------------------------------------------------------------ */

int worker_maintenance(struct worker *w, int64_t iter);

/* ------------------------------------------------------------------ */
/* worker unit                                                         */
/* ------------------------------------------------------------------ */

const char *shape_name(enum shape shape);
int parse_shape(const char *s, enum shape *out);
void *worker_main(void *arg);
void worker_fail(struct worker *w, const char *fmt, ...);

/* ------------------------------------------------------------------ */
/* summary unit                                                        */
/* ------------------------------------------------------------------ */

void read_rss(uint64_t *current, uint64_t *peak);
int pool_snapshot_alloc(int64_t **out, size_t *len);
int pool_snapshot_take(int64_t *dst, size_t len);
int final_summary(struct run_state *r, int64_t elapsed_ns);

/* ------------------------------------------------------------------ */
/* main unit                                                           */
/* ------------------------------------------------------------------ */

void log_line(const char *fmt, ...);
const char *on_off(bool b);
const char *policy_label(const char *env);

#endif /* ITB_LOOP_H */
