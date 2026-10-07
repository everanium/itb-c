/*
 * The worker: its thread body (one warmup iteration, the warmup
 * barrier, the main loop), one iteration, the session pump loop the
 * stream shape drives, and the round-trip comparison that decides
 * between a worker error and a data mismatch.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "loop.h"

static const char *const shape_names[] = {
    "stream", "message", "stream_one_shot", "both",
};

const char *shape_name(enum shape shape)
{
    return shape_names[shape];
}

int parse_shape(const char *s, enum shape *out)
{
    for (size_t i = 0; i < sizeof(shape_names) / sizeof(shape_names[0]); i++) {
        if (strcmp(s, shape_names[i]) == 0) {
            *out = (enum shape)i;
            return 0;
        }
    }
    return -1;
}

/* Records the worker's error text (first error wins) and requests a
 * stop of the whole run. */
void worker_fail(struct worker *w, const char *fmt, ...)
{
    if (!w->failed) {
        va_list ap;
        va_start(ap, fmt);
        (void)vsnprintf(w->error, sizeof(w->error), fmt, ap);
        va_end(ap);
        w->failed = true;
    }
    atomic_store(&w->run->stop, true);
}

/* ------------------------------------------------------------------ */
/* Growable buffer                                                     */
/* ------------------------------------------------------------------ */

int buf_append(struct buf *b, const uint8_t *src, size_t n)
{
    if (n == 0) {
        return 0;
    }
    if (b->len + n < b->len) {
        return -1;
    }
    if (b->len + n > b->cap) {
        size_t cap = b->cap > 0 ? b->cap : LOOP_PUMP_SLICE;
        while (cap < b->len + n) {
            if (cap > (SIZE_MAX >> 1)) {
                return -1;
            }
            cap *= 2;
        }
        uint8_t *grown = realloc(b->data, cap);
        if (grown == NULL) {
            return -1;
        }
        b->data = grown;
        b->cap = cap;
    }
    memcpy(b->data + b->len, src, n);
    b->len += n;
    return 0;
}

void buf_free(struct buf *b)
{
    free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

/* ------------------------------------------------------------------ */
/* Stream pump                                                         */
/* ------------------------------------------------------------------ */

/* Pump loop. The Go harness hands ITB an io.Reader / io.Writer pair
 * and ITB drives the chunk loop internally; the C ABI has no reader /
 * writer entry, so the caller drives it: open a session, feed slices
 * of at most 1 MiB, drain whatever the session has produced after
 * every write (a read before end never blocks), end, then drain until
 * the session reports finished (after end, a read on an empty spool
 * blocks until the terminal bytes arrive). The whole produced output
 * lands in the worker's reusable accumulator. The loop is written
 * here rather than delegated to the binding's pump convenience so it
 * stands in the utility, at the same place, in every language.
 * Returns 0, or -1 with the failing call and status in *what /
 * *status. */
static int pump(const itb_pipeline *pipe, bool encrypt,
                const uint8_t *src, size_t src_len, struct buf *out,
                const char **what, itb_status *status)
{
    itb_stream *stream = NULL;
    itb_status st = encrypt ? itb_pipeline_encrypt_stream_begin(pipe, &stream)
                            : itb_pipeline_decrypt_stream_begin(pipe, &stream);
    if (st != ITB_STATUS_OK) {
        *what = "StreamBegin";
        *status = st;
        return -1;
    }
    uint8_t *scratch = malloc(LOOP_PUMP_SLICE);
    if (scratch == NULL) {
        itb_stream_free(stream);
        *what = "malloc";
        *status = ITB_STATUS_INTERNAL;
        return -1;
    }
    out->len = 0;
    int rc = -1;
    size_t off = 0;
    while (off < src_len) {
        size_t slice = src_len - off;
        if (slice > LOOP_PUMP_SLICE) {
            slice = LOOP_PUMP_SLICE;
        }
        st = itb_stream_write(stream, src + off, slice);
        if (st != ITB_STATUS_OK) {
            *what = "StreamWrite";
            goto done;
        }
        off += slice;
        for (;;) {
            size_t n = 0;
            int fin = 0;
            st = itb_stream_read(stream, scratch, LOOP_PUMP_SLICE, &n, &fin);
            if (st != ITB_STATUS_OK) {
                *what = "StreamRead";
                goto done;
            }
            if (n == 0) {
                break;
            }
            if (buf_append(out, scratch, n) != 0) {
                st = ITB_STATUS_INTERNAL;
                *what = "buf_append";
                goto done;
            }
        }
    }
    st = itb_stream_end(stream);
    if (st != ITB_STATUS_OK) {
        *what = "StreamEnd";
        goto done;
    }
    for (;;) {
        size_t n = 0;
        int fin = 0;
        st = itb_stream_read(stream, scratch, LOOP_PUMP_SLICE, &n, &fin);
        if (st != ITB_STATUS_OK) {
            *what = "StreamRead";
            goto done;
        }
        if (buf_append(out, scratch, n) != 0) {
            st = ITB_STATUS_INTERNAL;
            *what = "buf_append";
            goto done;
        }
        if (fin) {
            break;
        }
    }
    rc = 0;
done:
    free(scratch);
    itb_stream_free(stream);
    *status = st;
    return rc;
}

/* ------------------------------------------------------------------ */
/* One iteration                                                       */
/* ------------------------------------------------------------------ */

/* First offset at which a and b differ; the shorter length when one
 * is a prefix of the other. */
static size_t first_difference(const uint8_t *a, size_t alen,
                               const uint8_t *b, size_t blen)
{
    size_t n = alen < blen ? alen : blen;
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            return i;
        }
    }
    return n;
}

/* Up to 16 bytes of buf from off as lowercase hex, or "-" when buf
 * has no bytes there. */
static void hex_window(const uint8_t *buf, size_t len, size_t off,
                       char *out, size_t cap)
{
    if (off >= len) {
        (void)snprintf(out, cap, "-");
        return;
    }
    size_t end = off + 16 < len ? off + 16 : len;
    size_t used = 0;
    for (size_t i = off; i < end && used + 3 <= cap; i++) {
        (void)snprintf(out + used, cap - used, "%02x", buf[i]);
        used += 2;
    }
}

/* Records a worker error for a failed cipher call. */
static void cipher_fail(struct worker *w, int64_t iter, enum shape shape,
                        const char *direction, const char *what, itb_status st)
{
    if (strcmp(what, direction) == 0) {
        worker_fail(w, "g%d iter %lld shape=%s: %s: status %d: %s",
                    w->id, (long long)iter, shape_name(shape), direction,
                    (int)st, itb_last_error());
    } else {
        worker_fail(w, "g%d iter %lld shape=%s: %s: %s: status %d: %s",
                    w->id, (long long)iter, shape_name(shape), direction, what,
                    (int)st, itb_last_error());
    }
}

/* One iteration. In order: refill the plaintext under rotating mode;
 * take the read lock; pick the surface; encrypt (timed); decrypt
 * (timed); compare the round-trip with the plaintext; bump the
 * counters; release the lock. The whole round-trip runs under the
 * read lock so handle-mutating maintenance (rekey, blob reopen) never
 * lands between an encrypt and its matching decrypt — maintenance
 * runs after this returns, from the worker loop. Returns 0, or -1
 * after recording the worker error. */
static int iterate(struct worker *w, int64_t iter)
{
    struct run_state *r = w->run;

    if (w->payload_mode == PAYLOAD_ROTATING) {
        if (fill_payload(PAYLOAD_ROTATING, w->seeded, &w->rng,
                         w->plaintext, w->plaintext_len) != 0) {
            worker_fail(w, "g%d iter %lld: payload refill: csprng", w->id, (long long)iter);
            return -1;
        }
    }

    pthread_rwlock_rdlock(&r->pipe_lock);

    /* Shape dispatch. message is one whole-buffer call on the Single
     * Message Pipeline; stream_one_shot is one whole-buffer call on
     * the streaming Pipeline (the C ABI's ITB_Triple_EncryptStream,
     * which routes to the same one-shot stream entry the Go
     * harness calls by name); stream opens a session on the same
     * streaming Pipeline and drives the chunk loop from here. Under
     * both the three rotate by iteration number so the session path
     * and the whole-buffer path alternate on one handle inside every
     * worker — the cross-path state-reuse hazard this harness exists
     * to catch. */
    enum shape shape = r->cfg.shape;
    if (shape == SHAPE_BOTH) {
        switch (iter % 3) {
        case 0:
            shape = SHAPE_STREAM;
            break;
        case 1:
            shape = SHAPE_MESSAGE;
            break;
        default:
            shape = SHAPE_STREAM_ONE_SHOT;
            break;
        }
    }

    /* C-specific. The message and one-shot entries allocate their
     * output; both buffers are released at the end of the iteration.
     * The pump accumulators are the worker's own and are reused. */
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    uint8_t *got = NULL;
    size_t got_len = 0;
    bool owned = false;
    int rc = -1;
    int64_t t0;
    const char *what = NULL;
    itb_status st = ITB_STATUS_OK;

    switch (shape) {
    case SHAPE_STREAM:
        t0 = now_ns();
        if (pump(r->stream_pipe, true, w->plaintext, w->plaintext_len,
                 &w->wire, &what, &st) != 0) {
            cipher_fail(w, iter, shape, "encrypt", what, st);
            goto out;
        }
        atomic_fetch_add(&w->nanos_enc, now_ns() - t0);
        t0 = now_ns();
        if (pump(r->stream_pipe, false, w->wire.data, w->wire.len,
                 &w->plain, &what, &st) != 0) {
            cipher_fail(w, iter, shape, "decrypt", what, st);
            goto out;
        }
        atomic_fetch_add(&w->nanos_dec, now_ns() - t0);
        got = w->plain.data;
        got_len = w->plain.len;
        break;
    case SHAPE_STREAM_ONE_SHOT:
        owned = true;
        t0 = now_ns();
        st = itb_pipeline_encrypt_stream_one_shot(r->stream_pipe, w->plaintext,
                                                  w->plaintext_len, &wire, &wire_len);
        if (st != ITB_STATUS_OK) {
            cipher_fail(w, iter, shape, "encrypt", "encrypt", st);
            goto out;
        }
        atomic_fetch_add(&w->nanos_enc, now_ns() - t0);
        t0 = now_ns();
        st = itb_pipeline_decrypt_stream_one_shot(r->stream_pipe, wire, wire_len,
                                                  &got, &got_len);
        if (st != ITB_STATUS_OK) {
            cipher_fail(w, iter, shape, "decrypt", "decrypt", st);
            goto out;
        }
        atomic_fetch_add(&w->nanos_dec, now_ns() - t0);
        break;
    case SHAPE_MESSAGE:
        owned = true;
        t0 = now_ns();
        st = itb_pipeline_encrypt_message(r->msg_pipe, w->plaintext,
                                          w->plaintext_len, &wire, &wire_len);
        if (st != ITB_STATUS_OK) {
            cipher_fail(w, iter, shape, "encrypt", "encrypt", st);
            goto out;
        }
        atomic_fetch_add(&w->nanos_enc, now_ns() - t0);
        t0 = now_ns();
        st = itb_pipeline_decrypt_message(r->msg_pipe, wire, wire_len,
                                          &got, &got_len);
        if (st != ITB_STATUS_OK) {
            cipher_fail(w, iter, shape, "decrypt", "decrypt", st);
            goto out;
        }
        atomic_fetch_add(&w->nanos_dec, now_ns() - t0);
        break;
    case SHAPE_BOTH:
        break; /* resolved above */
    }

    /* Failure model. A cipher call that returns a non-OK status is a
     * worker error: it is recorded, the run is asked to stop, the
     * other workers finish their in-flight iteration, and the error
     * is listed in the summary with the FAIL verdict. A round-trip
     * that returns OK with different bytes is a data mismatch: the
     * process terminates here, without summary or cleanup, because
     * the Pipeline state that produced the wrong bytes is the
     * evidence and nothing that runs afterwards may touch it. */
    if (got_len != w->plaintext_len
        || memcmp(w->plaintext, got, w->plaintext_len) != 0) {
        size_t off = first_difference(w->plaintext, w->plaintext_len, got, got_len);
        char want_hex[40];
        char got_hex[40];
        hex_window(w->plaintext, w->plaintext_len, off, want_hex, sizeof(want_hex));
        hex_window(got, got_len, off, got_hex, sizeof(got_hex));
        fprintf(stderr,
                "loop: DATA MISMATCH g%d iter %lld shape=%s: want %zu bytes, got %zu bytes, "
                "first difference at offset %zu: want %s got %s\n",
                w->id, (long long)iter, shape_name(shape), w->plaintext_len, got_len,
                off, want_hex, got_hex);
        fflush(stderr);
        _Exit(3);
    }

    atomic_fetch_add(&w->iters, 1);
    atomic_fetch_add(&w->bytes_enc, (int64_t)w->plaintext_len);
    atomic_fetch_add(&w->bytes_dec, (int64_t)got_len);
    rc = 0;

out:
    if (owned) {
        itb_bytes_free(wire);
        itb_bytes_free(got);
    }
    pthread_rwlock_unlock(&r->pipe_lock);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Thread body                                                         */
/* ------------------------------------------------------------------ */

/* Marks this worker returned; the last one to return stamps the
 * finish instant and wakes main. */
static void worker_done(struct run_state *r)
{
    pthread_mutex_lock(&r->done_mu);
    r->active--;
    if (r->active == 0) {
        r->finish_ns = now_ns();
        pthread_cond_signal(&r->done_cv);
    }
    pthread_mutex_unlock(&r->done_mu);
}

/* The worker thread body: one warmup iteration, the warmup barrier,
 * then the main loop until a stop is requested or the fixed
 * per-worker iteration budget (warmup included) is spent. A failing
 * warmup still passes both barriers so the launcher never waits on a
 * worker that has already given up. */
void *worker_main(void *arg)
{
    struct worker *w = arg;
    struct run_state *r = w->run;

    /* Warmup iteration — counted in the totals; its completion feeds
     * the post-warmup baselines. */
    int ok = iterate(w, 0);
    pthread_barrier_wait(&r->warmup_done);
    pthread_barrier_wait(&r->release);
    if (ok != 0) {
        worker_done(r);
        return NULL;
    }

    for (int64_t iter = 1;; iter++) {
        if (r->cfg.iterations > 0 && iter >= r->cfg.iterations) {
            break;
        }
        if (atomic_load(&r->stop)) {
            break;
        }
        if (iterate(w, iter) != 0) {
            break;
        }
        if (worker_maintenance(w, iter) != 0) {
            break;
        }
    }
    worker_done(r);
    return NULL;
}
