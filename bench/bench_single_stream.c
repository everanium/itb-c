/*
 * bench_single_stream.c -- Single Ouroboros streaming benchmarks for
 * the C binding.
 *
 * Eight cases exercising the full Single-Ouroboros streaming matrix at
 * 64 MiB total payload / 16 MiB chunk size under areion512 + 1024-bit
 * ITB key + hmac-blake3 MAC:
 *
 *     | Mode      | Op      | Variant   |
 *     |-----------|---------|-----------|
 *     | Easy      | Encrypt | AEAD IO   |
 *     | Easy      | Decrypt | AEAD IO   |
 *     | Easy      | Encrypt | UserLoop  |
 *     | Easy      | Decrypt | UserLoop  |
 *     | Low-Level | Encrypt | AEAD IO   |
 *     | Low-Level | Decrypt | AEAD IO   |
 *     | Low-Level | Encrypt | UserLoop  |
 *     | Low-Level | Decrypt | UserLoop  |
 *
 * AEAD IO  -- Streaming AEAD over caller-supplied read_fn / write_fn
 *             callbacks. Easy: itb_encryptor_stream_encrypt_auth /
 *             _decrypt_auth. Low-Level: itb_stream_encrypt_auth /
 *             itb_stream_decrypt_auth free functions over (noise,
 *             data, start, mac).
 *
 * UserLoop -- Plain Streaming via caller-side per-chunk loop; framing
 *             convention is a 4-byte big-endian ciphertext-length
 *             prefix preceding each chunk's ciphertext bytes (matching
 *             the canonical pattern in tmp/itb_examples/c/main.c).
 *             Easy uses itb_encryptor_encrypt / _decrypt; Low-Level
 *             uses itb_encrypt / itb_decrypt free functions.
 *
 * Setup discipline: 64 MiB CSPRNG fill, encryptor / Seed / MAC
 * construction, and (for Decrypt cases) the pre-encryption all run
 * outside the timer. Each measured iteration walks fresh in-memory
 * cursors over the prepared inputs / outputs and tears them down.
 *
 * Run with:
 *
 *   make bench
 *   ./bench/build/bench_single_stream
 *
 *   ITB_BENCH_FILTER=easy_encrypt_aead_io ./bench/build/bench_single_stream
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "itb.h"

#define STREAM_PRIMITIVE  "areion512"
#define STREAM_KEY_BITS   1024
#define STREAM_MAC_NAME   "hmac-blake3"
#define STREAM_TOTAL_BYTES ((size_t)(64u << 20))
#define STREAM_CHUNK_BYTES ((size_t)(16u << 20))

/* Fixed 32-byte MAC key matches itb_mac_new's 32-byte hmac-blake3
 * requirement. Value contents are immaterial for throughput
 * measurement; the MAC executes in O(MAC-key-length) per absorb
 * regardless of byte distribution. */
static const uint8_t STREAM_MAC_KEY[32] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
    0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01,
};

/* ---- In-memory read / write callbacks ----------------------------- */

/* Cursor over a const byte buffer with a position tracker. read_fn
 * returns successive 16 MiB-bounded slices until the buffer is
 * exhausted, then signals EOF. */
typedef struct mem_reader {
    const uint8_t *buf;
    size_t len;
    size_t pos;
} mem_reader_t;

static int mem_read_fn(void *ctx, void *buf, size_t cap, size_t *out_n) {
    mem_reader_t *r = (mem_reader_t *)ctx;
    size_t avail = r->len - r->pos;
    size_t take = (avail < cap) ? avail : cap;
    if (take > 0) {
        memcpy(buf, r->buf + r->pos, take);
        r->pos += take;
    }
    *out_n = take;
    return 0;
}

/* Growing byte sink. write_fn appends every chunk to the heap-resident
 * vec, doubling capacity on demand. Peak transient memory per
 * iteration: ~80 MiB for AEAD encrypt (64 MiB + ~16 MiB CSPRNG fill
 * expansion + 32-byte stream-id prefix). */
typedef struct mem_writer {
    uint8_t *buf;
    size_t len;
    size_t cap;
} mem_writer_t;

static int mem_write_grow(mem_writer_t *w, size_t need) {
    if (w->cap >= need) return 0;
    size_t new_cap = (w->cap == 0) ? 4096 : w->cap;
    while (new_cap < need) {
        if (new_cap > SIZE_MAX / 2) {
            new_cap = need;
            break;
        }
        new_cap *= 2;
    }
    uint8_t *p = (uint8_t *)realloc(w->buf, new_cap);
    if (p == NULL) return 1;
    w->buf = p;
    w->cap = new_cap;
    return 0;
}

static int mem_write_fn(void *ctx, const void *buf, size_t n) {
    mem_writer_t *w = (mem_writer_t *)ctx;
    if (mem_write_grow(w, w->len + n) != 0) {
        return 1;
    }
    memcpy(w->buf + w->len, buf, n);
    w->len += n;
    return 0;
}

static void mem_writer_init(mem_writer_t *w, size_t prealloc) {
    w->buf = NULL;
    w->len = 0;
    w->cap = 0;
    if (prealloc > 0) {
        w->buf = (uint8_t *)malloc(prealloc);
        if (w->buf == NULL) {
            fprintf(stderr, "mem_writer_init: prealloc %zu failed\n", prealloc);
            abort();
        }
        w->cap = prealloc;
    }
}

static void mem_writer_reset(mem_writer_t *w) {
    /* Drops the buffer entirely so each iteration starts from a fresh
     * empty sink; matches the Rust precedent's per-iter Vec::new().
     * Keeping the previous capacity around would mask the per-iter
     * growth cost from the measurement. */
    free(w->buf);
    w->buf = NULL;
    w->len = 0;
    w->cap = 0;
}

/* ---- 4-byte BE length-prefix UserLoop framing --------------------- */

static void frame_chunk(mem_writer_t *w, const uint8_t *ct, size_t ct_len) {
    uint8_t hdr[4];
    hdr[0] = (uint8_t)((ct_len >> 24) & 0xFF);
    hdr[1] = (uint8_t)((ct_len >> 16) & 0xFF);
    hdr[2] = (uint8_t)((ct_len >> 8) & 0xFF);
    hdr[3] = (uint8_t)(ct_len & 0xFF);
    if (mem_write_grow(w, w->len + 4 + ct_len) != 0) {
        fprintf(stderr, "frame_chunk: grow failed\n");
        abort();
    }
    memcpy(w->buf + w->len, hdr, 4);
    w->len += 4;
    memcpy(w->buf + w->len, ct, ct_len);
    w->len += ct_len;
}

/* ---- Construction helpers ---------------------------------------- */

static itb_encryptor_t *build_stream_encryptor(void) {
    itb_encryptor_t *e = NULL;
    itb_status_t s = itb_encryptor_new(STREAM_PRIMITIVE, STREAM_KEY_BITS,
                                        STREAM_MAC_NAME, 1, &e);
    if (s != ITB_OK || e == NULL) {
        fprintf(stderr, "itb_encryptor_new failed: %s\n", itb_last_error());
        abort();
    }
    if (env_lock_seed()) {
        s = itb_encryptor_set_lock_seed(e, 1);
        if (s != ITB_OK) {
            fprintf(stderr, "set_lock_seed(1) failed: %s\n", itb_last_error());
            abort();
        }
    }
    return e;
}

static void build_stream_seeds(itb_seed_t **n, itb_seed_t **d, itb_seed_t **s) {
    if (itb_seed_new(STREAM_PRIMITIVE, STREAM_KEY_BITS, n) != ITB_OK ||
        itb_seed_new(STREAM_PRIMITIVE, STREAM_KEY_BITS, d) != ITB_OK ||
        itb_seed_new(STREAM_PRIMITIVE, STREAM_KEY_BITS, s) != ITB_OK) {
        fprintf(stderr, "itb_seed_new failed: %s\n", itb_last_error());
        abort();
    }
}

static itb_mac_t *build_stream_mac(void) {
    itb_mac_t *m = NULL;
    itb_status_t s = itb_mac_new(STREAM_MAC_NAME, STREAM_MAC_KEY,
                                  sizeof(STREAM_MAC_KEY), &m);
    if (s != ITB_OK || m == NULL) {
        fprintf(stderr, "itb_mac_new failed: %s\n", itb_last_error());
        abort();
    }
    return m;
}

/* ---- Per-case context types ---------------------------------------- */
/*
 * Five separately-shaped contexts cover the eight bench cases:
 *   - easy_aead_io / easy_userloop : Encryptor + payload (+ pre-encrypted transcript on decrypt cases)
 *   - lowlevel_aead_io_encrypt: 3 Seeds + MAC + payload
 *   - lowlevel_aead_io_decrypt: 3 Seeds + MAC + transcript
 *   - lowlevel_userloop_encrypt: 3 Seeds + payload
 *   - lowlevel_userloop_decrypt: 3 Seeds + transcript
 *
 * Cleanup is registered against ctx_registry_t and freed once after
 * run_all returns.
 */
typedef struct case_ctx {
    /* Easy / shared-ownership */
    itb_encryptor_t *enc;
    /* Low-level seeds + MAC */
    itb_seed_t *noise;
    itb_seed_t *data;
    itb_seed_t *start;
    itb_mac_t  *mac;
    /* Plaintext source / transcript sink */
    uint8_t *payload;
    size_t   payload_len;
    uint8_t *transcript;
    size_t   transcript_len;
} case_ctx_t;

static case_ctx_t **g_ctx_registry = NULL;
static size_t g_ctx_registry_len = 0;
static size_t g_ctx_registry_cap = 0;

static case_ctx_t *ctx_new(void) {
    case_ctx_t *c = (case_ctx_t *)calloc(1, sizeof(*c));
    if (c == NULL) {
        fprintf(stderr, "ctx_new: out of memory\n");
        abort();
    }
    if (g_ctx_registry_len == g_ctx_registry_cap) {
        size_t new_cap = g_ctx_registry_cap == 0 ? 8 : g_ctx_registry_cap * 2;
        case_ctx_t **next =
            (case_ctx_t **)realloc(g_ctx_registry, new_cap * sizeof(*next));
        if (next == NULL) {
            fprintf(stderr, "ctx_new: registry grow failed\n");
            abort();
        }
        g_ctx_registry = next;
        g_ctx_registry_cap = new_cap;
    }
    g_ctx_registry[g_ctx_registry_len++] = c;
    return c;
}

static void ctx_free_all(void) {
    for (size_t i = 0; i < g_ctx_registry_len; i++) {
        case_ctx_t *c = g_ctx_registry[i];
        if (c == NULL) continue;
        if (c->enc != NULL) itb_encryptor_free(c->enc);
        if (c->noise != NULL) itb_seed_free(c->noise);
        if (c->data != NULL) itb_seed_free(c->data);
        if (c->start != NULL) itb_seed_free(c->start);
        if (c->mac != NULL) itb_mac_free(c->mac);
        free(c->payload);
        free(c->transcript);
        free(c);
    }
    free(g_ctx_registry);
    g_ctx_registry = NULL;
    g_ctx_registry_len = 0;
    g_ctx_registry_cap = 0;
}

/* ---- Per-iter callables: Easy AEAD IO ----------------------------- */

static void run_easy_encrypt_aead_io(void *vctx, uint64_t iters) {
    case_ctx_t *c = (case_ctx_t *)vctx;
    for (uint64_t i = 0; i < iters; i++) {
        mem_reader_t r = { c->payload, c->payload_len, 0 };
        mem_writer_t w; mem_writer_init(&w, STREAM_TOTAL_BYTES + (STREAM_TOTAL_BYTES >> 3));
        itb_status_t s = itb_encryptor_stream_encrypt_auth(
            c->enc, mem_read_fn, &r, mem_write_fn, &w, STREAM_CHUNK_BYTES);
        if (s != ITB_OK) {
            fprintf(stderr, "easy stream_encrypt_auth failed: %s\n", itb_last_error());
            abort();
        }
        mem_writer_reset(&w);
    }
}

static void run_easy_decrypt_aead_io(void *vctx, uint64_t iters) {
    case_ctx_t *c = (case_ctx_t *)vctx;
    for (uint64_t i = 0; i < iters; i++) {
        mem_reader_t r = { c->transcript, c->transcript_len, 0 };
        mem_writer_t w; mem_writer_init(&w, STREAM_TOTAL_BYTES);
        itb_status_t s = itb_encryptor_stream_decrypt_auth(
            c->enc, mem_read_fn, &r, mem_write_fn, &w, STREAM_CHUNK_BYTES);
        if (s != ITB_OK) {
            fprintf(stderr, "easy stream_decrypt_auth failed: %s\n", itb_last_error());
            abort();
        }
        mem_writer_reset(&w);
    }
}

/* ---- Per-iter callables: Easy UserLoop ---------------------------- */

static void run_easy_encrypt_userloop(void *vctx, uint64_t iters) {
    case_ctx_t *c = (case_ctx_t *)vctx;
    for (uint64_t i = 0; i < iters; i++) {
        mem_writer_t w; mem_writer_init(&w, STREAM_TOTAL_BYTES + (STREAM_TOTAL_BYTES >> 3));
        size_t off = 0;
        while (off < c->payload_len) {
            size_t end = off + STREAM_CHUNK_BYTES;
            if (end > c->payload_len) end = c->payload_len;
            uint8_t *ct = NULL;
            size_t ct_len = 0;
            itb_status_t s = itb_encryptor_encrypt(
                c->enc, c->payload + off, end - off, &ct, &ct_len);
            if (s != ITB_OK) {
                fprintf(stderr, "easy encrypt failed: %s\n", itb_last_error());
                abort();
            }
            frame_chunk(&w, ct, ct_len);
            itb_buffer_free(ct);
            off = end;
        }
        mem_writer_reset(&w);
    }
}

static void run_easy_decrypt_userloop(void *vctx, uint64_t iters) {
    case_ctx_t *c = (case_ctx_t *)vctx;
    for (uint64_t i = 0; i < iters; i++) {
        mem_writer_t w; mem_writer_init(&w, STREAM_TOTAL_BYTES);
        size_t off = 0;
        while (off + 4 <= c->transcript_len) {
            size_t ct_len =
                ((size_t)c->transcript[off] << 24) |
                ((size_t)c->transcript[off + 1] << 16) |
                ((size_t)c->transcript[off + 2] << 8) |
                ((size_t)c->transcript[off + 3]);
            off += 4;
            if (off + ct_len > c->transcript_len) {
                fprintf(stderr, "easy decrypt userloop: truncated transcript\n");
                abort();
            }
            uint8_t *pt = NULL;
            size_t pt_len = 0;
            itb_status_t s = itb_encryptor_decrypt(
                c->enc, c->transcript + off, ct_len, &pt, &pt_len);
            if (s != ITB_OK) {
                fprintf(stderr, "easy decrypt failed: %s\n", itb_last_error());
                abort();
            }
            if (mem_write_grow(&w, w.len + pt_len) != 0) {
                fprintf(stderr, "easy decrypt userloop: grow failed\n");
                abort();
            }
            memcpy(w.buf + w.len, pt, pt_len);
            w.len += pt_len;
            itb_buffer_free(pt);
            off += ct_len;
        }
        mem_writer_reset(&w);
    }
}

/* ---- Per-iter callables: Low-Level AEAD IO ------------------------ */

static void run_lowlevel_encrypt_aead_io(void *vctx, uint64_t iters) {
    case_ctx_t *c = (case_ctx_t *)vctx;
    for (uint64_t i = 0; i < iters; i++) {
        mem_reader_t r = { c->payload, c->payload_len, 0 };
        mem_writer_t w; mem_writer_init(&w, STREAM_TOTAL_BYTES + (STREAM_TOTAL_BYTES >> 3));
        itb_status_t s = itb_stream_encrypt_auth(
            c->noise, c->data, c->start, c->mac,
            mem_read_fn, &r, mem_write_fn, &w, STREAM_CHUNK_BYTES);
        if (s != ITB_OK) {
            fprintf(stderr, "low-level stream_encrypt_auth failed: %s\n", itb_last_error());
            abort();
        }
        mem_writer_reset(&w);
    }
}

static void run_lowlevel_decrypt_aead_io(void *vctx, uint64_t iters) {
    case_ctx_t *c = (case_ctx_t *)vctx;
    for (uint64_t i = 0; i < iters; i++) {
        mem_reader_t r = { c->transcript, c->transcript_len, 0 };
        mem_writer_t w; mem_writer_init(&w, STREAM_TOTAL_BYTES);
        itb_status_t s = itb_stream_decrypt_auth(
            c->noise, c->data, c->start, c->mac,
            mem_read_fn, &r, mem_write_fn, &w, STREAM_CHUNK_BYTES);
        if (s != ITB_OK) {
            fprintf(stderr, "low-level stream_decrypt_auth failed: %s\n", itb_last_error());
            abort();
        }
        mem_writer_reset(&w);
    }
}

/* ---- Per-iter callables: Low-Level UserLoop ----------------------- */

static void run_lowlevel_encrypt_userloop(void *vctx, uint64_t iters) {
    case_ctx_t *c = (case_ctx_t *)vctx;
    for (uint64_t i = 0; i < iters; i++) {
        mem_writer_t w; mem_writer_init(&w, STREAM_TOTAL_BYTES + (STREAM_TOTAL_BYTES >> 3));
        size_t off = 0;
        while (off < c->payload_len) {
            size_t end = off + STREAM_CHUNK_BYTES;
            if (end > c->payload_len) end = c->payload_len;
            uint8_t *ct = NULL;
            size_t ct_len = 0;
            itb_status_t s = itb_encrypt(c->noise, c->data, c->start,
                                          c->payload + off, end - off,
                                          &ct, &ct_len);
            if (s != ITB_OK) {
                fprintf(stderr, "low-level encrypt failed: %s\n", itb_last_error());
                abort();
            }
            frame_chunk(&w, ct, ct_len);
            itb_buffer_free(ct);
            off = end;
        }
        mem_writer_reset(&w);
    }
}

static void run_lowlevel_decrypt_userloop(void *vctx, uint64_t iters) {
    case_ctx_t *c = (case_ctx_t *)vctx;
    for (uint64_t i = 0; i < iters; i++) {
        mem_writer_t w; mem_writer_init(&w, STREAM_TOTAL_BYTES);
        size_t off = 0;
        while (off + 4 <= c->transcript_len) {
            size_t ct_len =
                ((size_t)c->transcript[off] << 24) |
                ((size_t)c->transcript[off + 1] << 16) |
                ((size_t)c->transcript[off + 2] << 8) |
                ((size_t)c->transcript[off + 3]);
            off += 4;
            if (off + ct_len > c->transcript_len) {
                fprintf(stderr, "low-level decrypt userloop: truncated transcript\n");
                abort();
            }
            uint8_t *pt = NULL;
            size_t pt_len = 0;
            itb_status_t s = itb_decrypt(c->noise, c->data, c->start,
                                          c->transcript + off, ct_len,
                                          &pt, &pt_len);
            if (s != ITB_OK) {
                fprintf(stderr, "low-level decrypt failed: %s\n", itb_last_error());
                abort();
            }
            if (mem_write_grow(&w, w.len + pt_len) != 0) {
                fprintf(stderr, "low-level decrypt userloop: grow failed\n");
                abort();
            }
            memcpy(w.buf + w.len, pt, pt_len);
            w.len += pt_len;
            itb_buffer_free(pt);
            off += ct_len;
        }
        mem_writer_reset(&w);
    }
}

/* ---- Pre-encryption helpers (decrypt-side setup) ------------------ */

/* Builds the AEAD IO transcript once via the same code path the
 * encrypt-side benchmark exercises, then captures it for the
 * decrypt-side iter to consume. */
static void prebuild_easy_aead_transcript(case_ctx_t *c) {
    mem_reader_t r = { c->payload, c->payload_len, 0 };
    mem_writer_t w; mem_writer_init(&w, STREAM_TOTAL_BYTES + (STREAM_TOTAL_BYTES >> 3));
    itb_status_t s = itb_encryptor_stream_encrypt_auth(
        c->enc, mem_read_fn, &r, mem_write_fn, &w, STREAM_CHUNK_BYTES);
    if (s != ITB_OK) {
        fprintf(stderr, "prebuild easy AEAD transcript failed: %s\n", itb_last_error());
        abort();
    }
    c->transcript = w.buf;
    c->transcript_len = w.len;
}

static void prebuild_lowlevel_aead_transcript(case_ctx_t *c) {
    mem_reader_t r = { c->payload, c->payload_len, 0 };
    mem_writer_t w; mem_writer_init(&w, STREAM_TOTAL_BYTES + (STREAM_TOTAL_BYTES >> 3));
    itb_status_t s = itb_stream_encrypt_auth(
        c->noise, c->data, c->start, c->mac,
        mem_read_fn, &r, mem_write_fn, &w, STREAM_CHUNK_BYTES);
    if (s != ITB_OK) {
        fprintf(stderr, "prebuild low-level AEAD transcript failed: %s\n", itb_last_error());
        abort();
    }
    c->transcript = w.buf;
    c->transcript_len = w.len;
}

/* Pre-frames the UserLoop length-prefixed transcript via the matching
 * per-chunk encrypt call. Easy uses Encryptor; Low-Level uses the
 * free-function itb_encrypt. */
static void prebuild_easy_userloop_transcript(case_ctx_t *c) {
    mem_writer_t w; mem_writer_init(&w, STREAM_TOTAL_BYTES + (STREAM_TOTAL_BYTES >> 3));
    size_t off = 0;
    while (off < c->payload_len) {
        size_t end = off + STREAM_CHUNK_BYTES;
        if (end > c->payload_len) end = c->payload_len;
        uint8_t *ct = NULL;
        size_t ct_len = 0;
        itb_status_t s = itb_encryptor_encrypt(c->enc, c->payload + off, end - off,
                                                &ct, &ct_len);
        if (s != ITB_OK) {
            fprintf(stderr, "prebuild easy UserLoop chunk failed: %s\n", itb_last_error());
            abort();
        }
        frame_chunk(&w, ct, ct_len);
        itb_buffer_free(ct);
        off = end;
    }
    c->transcript = w.buf;
    c->transcript_len = w.len;
}

static void prebuild_lowlevel_userloop_transcript(case_ctx_t *c) {
    mem_writer_t w; mem_writer_init(&w, STREAM_TOTAL_BYTES + (STREAM_TOTAL_BYTES >> 3));
    size_t off = 0;
    while (off < c->payload_len) {
        size_t end = off + STREAM_CHUNK_BYTES;
        if (end > c->payload_len) end = c->payload_len;
        uint8_t *ct = NULL;
        size_t ct_len = 0;
        itb_status_t s = itb_encrypt(c->noise, c->data, c->start,
                                      c->payload + off, end - off,
                                      &ct, &ct_len);
        if (s != ITB_OK) {
            fprintf(stderr, "prebuild low-level UserLoop chunk failed: %s\n", itb_last_error());
            abort();
        }
        frame_chunk(&w, ct, ct_len);
        itb_buffer_free(ct);
        off = end;
    }
    c->transcript = w.buf;
    c->transcript_len = w.len;
}

/* ---- Case constructors -------------------------------------------- */

static bench_case_t make_easy_encrypt_aead_io(char *name) {
    case_ctx_t *c = ctx_new();
    c->enc = build_stream_encryptor();
    c->payload = random_bytes_alloc(STREAM_TOTAL_BYTES);
    c->payload_len = STREAM_TOTAL_BYTES;
    bench_case_t bc = { name, run_easy_encrypt_aead_io, c, STREAM_TOTAL_BYTES };
    return bc;
}

static bench_case_t make_easy_decrypt_aead_io(char *name) {
    case_ctx_t *c = ctx_new();
    c->enc = build_stream_encryptor();
    c->payload = random_bytes_alloc(STREAM_TOTAL_BYTES);
    c->payload_len = STREAM_TOTAL_BYTES;
    prebuild_easy_aead_transcript(c);
    bench_case_t bc = { name, run_easy_decrypt_aead_io, c, STREAM_TOTAL_BYTES };
    return bc;
}

static bench_case_t make_easy_encrypt_userloop(char *name) {
    case_ctx_t *c = ctx_new();
    c->enc = build_stream_encryptor();
    c->payload = random_bytes_alloc(STREAM_TOTAL_BYTES);
    c->payload_len = STREAM_TOTAL_BYTES;
    bench_case_t bc = { name, run_easy_encrypt_userloop, c, STREAM_TOTAL_BYTES };
    return bc;
}

static bench_case_t make_easy_decrypt_userloop(char *name) {
    case_ctx_t *c = ctx_new();
    c->enc = build_stream_encryptor();
    c->payload = random_bytes_alloc(STREAM_TOTAL_BYTES);
    c->payload_len = STREAM_TOTAL_BYTES;
    prebuild_easy_userloop_transcript(c);
    bench_case_t bc = { name, run_easy_decrypt_userloop, c, STREAM_TOTAL_BYTES };
    return bc;
}

static bench_case_t make_lowlevel_encrypt_aead_io(char *name) {
    case_ctx_t *c = ctx_new();
    build_stream_seeds(&c->noise, &c->data, &c->start);
    c->mac = build_stream_mac();
    c->payload = random_bytes_alloc(STREAM_TOTAL_BYTES);
    c->payload_len = STREAM_TOTAL_BYTES;
    bench_case_t bc = { name, run_lowlevel_encrypt_aead_io, c, STREAM_TOTAL_BYTES };
    return bc;
}

static bench_case_t make_lowlevel_decrypt_aead_io(char *name) {
    case_ctx_t *c = ctx_new();
    build_stream_seeds(&c->noise, &c->data, &c->start);
    c->mac = build_stream_mac();
    c->payload = random_bytes_alloc(STREAM_TOTAL_BYTES);
    c->payload_len = STREAM_TOTAL_BYTES;
    prebuild_lowlevel_aead_transcript(c);
    bench_case_t bc = { name, run_lowlevel_decrypt_aead_io, c, STREAM_TOTAL_BYTES };
    return bc;
}

static bench_case_t make_lowlevel_encrypt_userloop(char *name) {
    case_ctx_t *c = ctx_new();
    build_stream_seeds(&c->noise, &c->data, &c->start);
    c->payload = random_bytes_alloc(STREAM_TOTAL_BYTES);
    c->payload_len = STREAM_TOTAL_BYTES;
    bench_case_t bc = { name, run_lowlevel_encrypt_userloop, c, STREAM_TOTAL_BYTES };
    return bc;
}

static bench_case_t make_lowlevel_decrypt_userloop(char *name) {
    case_ctx_t *c = ctx_new();
    build_stream_seeds(&c->noise, &c->data, &c->start);
    c->payload = random_bytes_alloc(STREAM_TOTAL_BYTES);
    c->payload_len = STREAM_TOTAL_BYTES;
    prebuild_lowlevel_userloop_transcript(c);
    bench_case_t bc = { name, run_lowlevel_decrypt_userloop, c, STREAM_TOTAL_BYTES };
    return bc;
}

/* ---- Case-list assembly ------------------------------------------- */

#define TOTAL_CASES 8

#define NAME_PREFIX  "bench_single_stream_areion512_1024bit_64mb"

static size_t build_cases(bench_case_t *cases) {
    size_t idx = 0;
    cases[idx++] = make_easy_encrypt_aead_io(
        bench_strdup_fmt("%s_easy_encrypt_aead_io", NAME_PREFIX));
    cases[idx++] = make_easy_decrypt_aead_io(
        bench_strdup_fmt("%s_easy_decrypt_aead_io", NAME_PREFIX));
    cases[idx++] = make_easy_encrypt_userloop(
        bench_strdup_fmt("%s_easy_encrypt_userloop", NAME_PREFIX));
    cases[idx++] = make_easy_decrypt_userloop(
        bench_strdup_fmt("%s_easy_decrypt_userloop", NAME_PREFIX));
    cases[idx++] = make_lowlevel_encrypt_aead_io(
        bench_strdup_fmt("%s_lowlevel_encrypt_aead_io", NAME_PREFIX));
    cases[idx++] = make_lowlevel_decrypt_aead_io(
        bench_strdup_fmt("%s_lowlevel_decrypt_aead_io", NAME_PREFIX));
    cases[idx++] = make_lowlevel_encrypt_userloop(
        bench_strdup_fmt("%s_lowlevel_encrypt_userloop", NAME_PREFIX));
    cases[idx++] = make_lowlevel_decrypt_userloop(
        bench_strdup_fmt("%s_lowlevel_decrypt_userloop", NAME_PREFIX));
    return idx;
}

int main(void) {
    int nonce_bits = env_nonce_bits(128);
    if (itb_set_max_workers(0) != ITB_OK) {
        fprintf(stderr, "itb_set_max_workers(0) failed: %s\n", itb_last_error());
        return 1;
    }
    if (itb_set_nonce_bits(nonce_bits) != ITB_OK) {
        fprintf(stderr, "itb_set_nonce_bits(%d) failed: %s\n",
                nonce_bits, itb_last_error());
        return 1;
    }

    printf("# single_stream payload_bytes=%zu chunk_bytes=%zu primitive=%s "
           "key_bits=%d mac=%s nonce_bits=%d lockseed=%s workers=auto\n",
           STREAM_TOTAL_BYTES, STREAM_CHUNK_BYTES, STREAM_PRIMITIVE,
           STREAM_KEY_BITS, STREAM_MAC_NAME, nonce_bits,
           env_lock_seed() ? "on" : "off");
    fflush(stdout);

    bench_case_t cases[TOTAL_CASES];
    size_t n = build_cases(cases);
    run_all(cases, n);
    ctx_free_all();
    return 0;
}
