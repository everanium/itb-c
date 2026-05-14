/*
 * streams.c — chunked encrypt / decrypt over caller-owned read / write
 * callbacks.
 *
 * Mirrors Rust src/streams.rs / D src/itb/streams.d. ITB ciphertexts
 * cap at ~64 MB plaintext per chunk (the underlying container size
 * limit); streaming larger payloads slices the input into
 * chunk_size-sized blocks at the binding layer, encrypts each through
 * the regular itb_encrypt / itb_encrypt_auth FFI path, and
 * concatenates the results. The reverse operation walks a
 * concatenated chunk stream by reading the chunk header, calling
 * itb_parse_chunk_len to learn the chunk's body length, reading that
 * many bytes, and decrypting the single chunk.
 *
 * Free-function shape. The streams take Seeds (and an optional MAC),
 * NOT an itb_encryptor_t handle — matching the canonical
 * cross-binding stream contract. The Rust / Python / D / Ada
 * source-of-truth shape is Seed-passing; handle-passing is
 * deliberately not exposed here.
 *
 * Callback design. Caller supplies a (read_fn, user_ctx) pair for the
 * input source and a (write_fn, user_ctx) pair for the output sink;
 * the same pointer-style approach lets the caller carry state (file
 * descriptor, std::ostream, in-memory buffer, etc.) without globals.
 * read_fn signals EOF via *out_n = 0; write_fn must consume the full
 * (buf, n) span before returning. Either callback returning a
 * non-zero status code aborts the stream operation with ITB_INTERNAL.
 *
 * Memory peak. Bounded by chunk_size regardless of payload length.
 * The caller picks chunk_size explicitly (must be > 0; ITB_DEFAULT_CHUNK_SIZE
 * = 16 MiB is exposed in the public header as a recommended starting
 * value). The encrypt direction
 * allocates one read buffer (chunk_size bytes) plus one ciphertext
 * buffer per chunk via itb_encrypt; the decrypt direction grows an
 * accumulator buffer until a full chunk is available, then drains
 * it.
 *
 * Threading. A stream call is not thread-safe internally — its state
 * lives on the call stack and is single-threaded. Distinct stream
 * calls, each on its own thread, run independently against the
 * libitb worker pool.
 */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

/* ------------------------------------------------------------------ */
/* Internal helpers                                                    */
/* ------------------------------------------------------------------ */

/* Validates chunk_size against the cross-binding contract: zero is
 * rejected (mirroring Rust / D / Python which reject a zero-chunk
 * stream as malformed input). The caller passes the validated value
 * through to the inner loop unchanged. */
static itb_status_t validate_chunk_size(size_t chunk_size)
{
    if (chunk_size == 0) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "chunk_size must be > 0");
    }
    return ITB_OK;
}

/*
 * write_fn return-code translator. Surface caller's I/O failure via
 * ITB_INTERNAL with a fixed diagnostic; the caller's own context can
 * retrieve the precise underlying error via the (user_ctx) pointer.
 */
static itb_status_t io_write_error(int rc)
{
    (void) rc;
    return itb_internal_set_error_msg(
        ITB_INTERNAL, "stream write_fn reported I/O error");
}

static itb_status_t io_read_error(int rc)
{
    (void) rc;
    return itb_internal_set_error_msg(
        ITB_INTERNAL, "stream read_fn reported I/O error");
}

/* ------------------------------------------------------------------ */
/* Encrypt direction — Single Ouroboros                                 */
/* ------------------------------------------------------------------ */

static itb_status_t encrypt_emit_single(const itb_seed_t *noise,
                                        const itb_seed_t *data,
                                        const itb_seed_t *start,
                                        const uint8_t *chunk,
                                        size_t chunk_len,
                                        itb_stream_write_fn write_fn,
                                        void *write_ctx)
{
    uint8_t *ct = NULL;
    size_t ct_len = 0;
    itb_status_t st = itb_encrypt(noise, data, start, chunk, chunk_len,
                                  &ct, &ct_len);
    if (st != ITB_OK) {
        return st;
    }
    if (ct_len > 0) {
        int wrc = write_fn(write_ctx, ct, ct_len);
        if (wrc != 0) {
            memset(ct, 0, ct_len);
            free(ct);
            return io_write_error(wrc);
        }
    }
    if (ct_len > 0) memset(ct, 0, ct_len);
    free(ct);
    return ITB_OK;
}

static itb_status_t encrypt_loop_single(const itb_seed_t *noise,
                                        const itb_seed_t *data,
                                        const itb_seed_t *start,
                                        itb_stream_read_fn read_fn,
                                        void *read_ctx,
                                        itb_stream_write_fn write_fn,
                                        void *write_ctx,
                                        size_t chunk_size)
{
    uint8_t *buf = (uint8_t *) malloc(chunk_size);
    if (buf == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }
    size_t buffered = 0;

    for (;;) {
        /* Fill buf up to chunk_size, draining read_fn until either we
         * have a full chunk or read_fn signals EOF (*got = 0). */
        if (buffered < chunk_size) {
            size_t got = 0;
            int rrc = read_fn(read_ctx, buf + buffered,
                              chunk_size - buffered, &got);
            if (rrc != 0) {
                memset(buf, 0, chunk_size);
                free(buf);
                return io_read_error(rrc);
            }
            if (got == 0) {
                /* EOF — flush partial chunk if any, then stop. */
                if (buffered > 0) {
                    itb_status_t st = encrypt_emit_single(
                        noise, data, start, buf, buffered,
                        write_fn, write_ctx);
                    if (st != ITB_OK) {
                        memset(buf, 0, chunk_size);
                        free(buf);
                        return st;
                    }
                }
                memset(buf, 0, chunk_size);
                free(buf);
                itb_internal_reset_error();
                return ITB_OK;
            }
            buffered += got;
            continue;
        }
        /* buf is full — emit one chunk and reset. */
        itb_status_t st = encrypt_emit_single(
            noise, data, start, buf, chunk_size, write_fn, write_ctx);
        if (st != ITB_OK) {
            memset(buf, 0, chunk_size);
            free(buf);
            return st;
        }
        /* Zero the consumed plaintext between emit iterations. */
        memset(buf, 0, chunk_size);
        buffered = 0;
    }
}

/* ------------------------------------------------------------------ */
/* Encrypt direction — Triple Ouroboros                                 */
/* ------------------------------------------------------------------ */

static itb_status_t encrypt_emit_triple(const itb_seed_t *noise,
                                        const itb_seed_t *data1,
                                        const itb_seed_t *data2,
                                        const itb_seed_t *data3,
                                        const itb_seed_t *start1,
                                        const itb_seed_t *start2,
                                        const itb_seed_t *start3,
                                        const uint8_t *chunk,
                                        size_t chunk_len,
                                        itb_stream_write_fn write_fn,
                                        void *write_ctx)
{
    uint8_t *ct = NULL;
    size_t ct_len = 0;
    itb_status_t st = itb_encrypt_triple(noise, data1, data2, data3,
                                         start1, start2, start3,
                                         chunk, chunk_len, &ct, &ct_len);
    if (st != ITB_OK) {
        return st;
    }
    if (ct_len > 0) {
        int wrc = write_fn(write_ctx, ct, ct_len);
        if (wrc != 0) {
            memset(ct, 0, ct_len);
            free(ct);
            return io_write_error(wrc);
        }
    }
    if (ct_len > 0) memset(ct, 0, ct_len);
    free(ct);
    return ITB_OK;
}

static itb_status_t encrypt_loop_triple(const itb_seed_t *noise,
                                        const itb_seed_t *data1,
                                        const itb_seed_t *data2,
                                        const itb_seed_t *data3,
                                        const itb_seed_t *start1,
                                        const itb_seed_t *start2,
                                        const itb_seed_t *start3,
                                        itb_stream_read_fn read_fn,
                                        void *read_ctx,
                                        itb_stream_write_fn write_fn,
                                        void *write_ctx,
                                        size_t chunk_size)
{
    uint8_t *buf = (uint8_t *) malloc(chunk_size);
    if (buf == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }
    size_t buffered = 0;

    for (;;) {
        if (buffered < chunk_size) {
            size_t got = 0;
            int rrc = read_fn(read_ctx, buf + buffered,
                              chunk_size - buffered, &got);
            if (rrc != 0) {
                memset(buf, 0, chunk_size);
                free(buf);
                return io_read_error(rrc);
            }
            if (got == 0) {
                if (buffered > 0) {
                    itb_status_t st = encrypt_emit_triple(
                        noise, data1, data2, data3,
                        start1, start2, start3,
                        buf, buffered, write_fn, write_ctx);
                    if (st != ITB_OK) {
                        memset(buf, 0, chunk_size);
                        free(buf);
                        return st;
                    }
                }
                memset(buf, 0, chunk_size);
                free(buf);
                itb_internal_reset_error();
                return ITB_OK;
            }
            buffered += got;
            continue;
        }
        itb_status_t st = encrypt_emit_triple(
            noise, data1, data2, data3,
            start1, start2, start3,
            buf, chunk_size, write_fn, write_ctx);
        if (st != ITB_OK) {
            memset(buf, 0, chunk_size);
            free(buf);
            return st;
        }
        memset(buf, 0, chunk_size);
        buffered = 0;
    }
}

/* ------------------------------------------------------------------ */
/* Decrypt direction — accumulator + drain                              */
/* ------------------------------------------------------------------ */

/* Grows the accumulator buffer to at least `need` bytes, reusing
 * existing capacity where possible. Returns ITB_OK on success or
 * ITB_INTERNAL on allocation failure. */
static itb_status_t accum_grow(uint8_t **buf, size_t *cap, size_t need)
{
    if (*cap >= need) return ITB_OK;
    size_t new_cap = (*cap == 0) ? 4096 : *cap;
    while (new_cap < need) {
        if (new_cap > SIZE_MAX / 2) {
            new_cap = need;
            break;
        }
        new_cap *= 2;
    }
    uint8_t *p = (uint8_t *) realloc(*buf, new_cap);
    if (p == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "realloc failed");
    }
    *buf = p;
    *cap = new_cap;
    /* Documents the post-condition for static analyzers (Phase 8 Agent 5
     * surfaced an interprocedural-aliasing FP class — `accum_grow`'s
     * `*buf != NULL` post-condition was not tracked across call boundaries
     * by gcc -fanalyzer / scan-build). Compiles out under -DNDEBUG. */
    assert(*buf != NULL);
    return ITB_OK;
}

/* Drops the consumed prefix of length `n` from the accumulator,
 * sliding the remaining bytes down. */
static void accum_consume(uint8_t *buf, size_t *len, size_t n)
{
    if (n >= *len) {
        *len = 0;
        return;
    }
    /* `buf` is non-NULL on every call site (`drain_single` / `drain_triple`
     * only reach here after `*len > 0`, which implies a prior `accum_grow`
     * has populated the accumulator). The assert documents the post-
     * condition for static analyzers; compiles out under -DNDEBUG. */
    assert(buf != NULL);
    memmove(buf, buf + n, *len - n);
    *len -= n;
    /* Zero the freed tail so plaintext does not linger in the
     * accumulator's unused capacity between drain iterations. */
    memset(buf + *len, 0, n);
}

/* Drains every full chunk currently sitting in the accumulator,
 * decrypting each and emitting plaintext via write_fn. Returns once
 * the buffer either holds < header_size bytes OR holds < chunk_len
 * bytes (announced by the header) — i.e. needs more input. */
static itb_status_t drain_single(const itb_seed_t *noise,
                                 const itb_seed_t *data,
                                 const itb_seed_t *start,
                                 size_t header_size,
                                 uint8_t *buf, size_t *buf_len,
                                 itb_stream_write_fn write_fn,
                                 void *write_ctx)
{
    for (;;) {
        if (*buf_len < header_size) return ITB_OK;
        size_t chunk_len = 0;
        itb_status_t st = itb_parse_chunk_len(buf, header_size, &chunk_len);
        if (st != ITB_OK) {
            return st;
        }
        if (chunk_len == 0 || *buf_len < chunk_len) return ITB_OK;

        uint8_t *pt = NULL;
        size_t pt_len = 0;
        st = itb_decrypt(noise, data, start, buf, chunk_len, &pt, &pt_len);
        if (st != ITB_OK) {
            return st;
        }
        if (pt_len > 0) {
            int wrc = write_fn(write_ctx, pt, pt_len);
            if (wrc != 0) {
                memset(pt, 0, pt_len);
                free(pt);
                return io_write_error(wrc);
            }
        }
        if (pt_len > 0) memset(pt, 0, pt_len);
        free(pt);
        accum_consume(buf, buf_len, chunk_len);
    }
}

static itb_status_t drain_triple(const itb_seed_t *noise,
                                 const itb_seed_t *data1,
                                 const itb_seed_t *data2,
                                 const itb_seed_t *data3,
                                 const itb_seed_t *start1,
                                 const itb_seed_t *start2,
                                 const itb_seed_t *start3,
                                 size_t header_size,
                                 uint8_t *buf, size_t *buf_len,
                                 itb_stream_write_fn write_fn,
                                 void *write_ctx)
{
    for (;;) {
        if (*buf_len < header_size) return ITB_OK;
        size_t chunk_len = 0;
        itb_status_t st = itb_parse_chunk_len(buf, header_size, &chunk_len);
        if (st != ITB_OK) {
            return st;
        }
        if (chunk_len == 0 || *buf_len < chunk_len) return ITB_OK;

        uint8_t *pt = NULL;
        size_t pt_len = 0;
        st = itb_decrypt_triple(noise, data1, data2, data3,
                                start1, start2, start3,
                                buf, chunk_len, &pt, &pt_len);
        if (st != ITB_OK) {
            return st;
        }
        if (pt_len > 0) {
            int wrc = write_fn(write_ctx, pt, pt_len);
            if (wrc != 0) {
                memset(pt, 0, pt_len);
                free(pt);
                return io_write_error(wrc);
            }
        }
        if (pt_len > 0) memset(pt, 0, pt_len);
        free(pt);
        accum_consume(buf, buf_len, chunk_len);
    }
}

static itb_status_t decrypt_loop_single(const itb_seed_t *noise,
                                        const itb_seed_t *data,
                                        const itb_seed_t *start,
                                        itb_stream_read_fn read_fn,
                                        void *read_ctx,
                                        itb_stream_write_fn write_fn,
                                        void *write_ctx,
                                        size_t chunk_size)
{
    /* Snapshot the chunk-header size at call entry; switching nonce
     * bits mid-stream would invalidate this. Same contract as Rust
     * StreamDecryptor::new. */
    int hsz_int = itb_header_size();
    if (hsz_int <= 0) {
        return itb_internal_set_error_msg(
            ITB_INTERNAL, "itb_header_size returned non-positive value");
    }
    size_t header_size = (size_t) hsz_int;

    uint8_t *accum = NULL;
    size_t accum_cap = 0;
    size_t accum_len = 0;

    uint8_t *read_buf = (uint8_t *) malloc(chunk_size);
    if (read_buf == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }

    for (;;) {
        size_t got = 0;
        int rrc = read_fn(read_ctx, read_buf, chunk_size, &got);
        if (rrc != 0) {
            free(read_buf);
            free(accum);
            return io_read_error(rrc);
        }
        if (got == 0) {
            /* EOF — accumulator must be empty for a clean stream. A
             * non-empty tail at EOF is a half-chunk error (mirrors
             * Rust StreamDecryptor::close). */
            itb_status_t st = ITB_OK;
            if (accum_len > 0) {
                st = itb_internal_set_error_msg(
                    ITB_BAD_INPUT,
                    "stream decrypt: trailing bytes do not form a complete chunk");
            }
            free(read_buf);
            free(accum);
            if (st == ITB_OK) {
                itb_internal_reset_error();
            }
            return st;
        }
        /* Append `got` bytes to the accumulator. */
        itb_status_t gst = accum_grow(&accum, &accum_cap, accum_len + got);
        if (gst != ITB_OK) {
            free(read_buf);
            free(accum);
            return gst;
        }
        /* `accum_grow` guarantees `accum != NULL` on ITB_OK; restate for
         * the analyzer (interprocedural-aliasing FP class — the
         * helper's post-condition is not tracked across the call). */
        assert(accum != NULL);
        memcpy(accum + accum_len, read_buf, got);
        accum_len += got;

        itb_status_t dst = drain_single(noise, data, start,
                                        header_size,
                                        accum, &accum_len,
                                        write_fn, write_ctx);
        if (dst != ITB_OK) {
            free(read_buf);
            free(accum);
            return dst;
        }
    }
}

static itb_status_t decrypt_loop_triple(const itb_seed_t *noise,
                                        const itb_seed_t *data1,
                                        const itb_seed_t *data2,
                                        const itb_seed_t *data3,
                                        const itb_seed_t *start1,
                                        const itb_seed_t *start2,
                                        const itb_seed_t *start3,
                                        itb_stream_read_fn read_fn,
                                        void *read_ctx,
                                        itb_stream_write_fn write_fn,
                                        void *write_ctx,
                                        size_t chunk_size)
{
    int hsz_int = itb_header_size();
    if (hsz_int <= 0) {
        return itb_internal_set_error_msg(
            ITB_INTERNAL, "itb_header_size returned non-positive value");
    }
    size_t header_size = (size_t) hsz_int;

    uint8_t *accum = NULL;
    size_t accum_cap = 0;
    size_t accum_len = 0;

    uint8_t *read_buf = (uint8_t *) malloc(chunk_size);
    if (read_buf == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }

    for (;;) {
        size_t got = 0;
        int rrc = read_fn(read_ctx, read_buf, chunk_size, &got);
        if (rrc != 0) {
            free(read_buf);
            free(accum);
            return io_read_error(rrc);
        }
        if (got == 0) {
            itb_status_t st = ITB_OK;
            if (accum_len > 0) {
                st = itb_internal_set_error_msg(
                    ITB_BAD_INPUT,
                    "stream decrypt: trailing bytes do not form a complete chunk");
            }
            free(read_buf);
            free(accum);
            if (st == ITB_OK) {
                itb_internal_reset_error();
            }
            return st;
        }
        itb_status_t gst = accum_grow(&accum, &accum_cap, accum_len + got);
        if (gst != ITB_OK) {
            free(read_buf);
            free(accum);
            return gst;
        }
        /* `accum_grow` guarantees `accum != NULL` on ITB_OK; restate for
         * the analyzer (interprocedural-aliasing FP class). */
        assert(accum != NULL);
        memcpy(accum + accum_len, read_buf, got);
        accum_len += got;

        itb_status_t dst = drain_triple(
            noise, data1, data2, data3,
            start1, start2, start3,
            header_size, accum, &accum_len, write_fn, write_ctx);
        if (dst != ITB_OK) {
            free(read_buf);
            free(accum);
            return dst;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Argument validation helpers                                         */
/* ------------------------------------------------------------------ */

static itb_status_t validate_callbacks(itb_stream_read_fn read_fn,
                                       itb_stream_write_fn write_fn)
{
    if (read_fn == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "read_fn callback is NULL");
    }
    if (write_fn == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "write_fn callback is NULL");
    }
    return ITB_OK;
}

/* ------------------------------------------------------------------ */
/* Public entry points                                                 */
/* ------------------------------------------------------------------ */

itb_status_t itb_stream_encrypt(const itb_seed_t *noise,
                                const itb_seed_t *data,
                                const itb_seed_t *start,
                                itb_stream_read_fn read_fn, void *read_user_ctx,
                                itb_stream_write_fn write_fn, void *write_user_ctx,
                                size_t chunk_size)
{
    if (noise == NULL || data == NULL || start == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "noise/data/start seed is NULL");
    }
    itb_status_t cv = validate_callbacks(read_fn, write_fn);
    if (cv != ITB_OK) return cv;
    itb_status_t sv = validate_chunk_size(chunk_size);
    if (sv != ITB_OK) return sv;
    return encrypt_loop_single(noise, data, start,
                               read_fn, read_user_ctx,
                               write_fn, write_user_ctx,
                               chunk_size);
}

itb_status_t itb_stream_decrypt(const itb_seed_t *noise,
                                const itb_seed_t *data,
                                const itb_seed_t *start,
                                itb_stream_read_fn read_fn, void *read_user_ctx,
                                itb_stream_write_fn write_fn, void *write_user_ctx,
                                size_t chunk_size)
{
    if (noise == NULL || data == NULL || start == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "noise/data/start seed is NULL");
    }
    itb_status_t cv = validate_callbacks(read_fn, write_fn);
    if (cv != ITB_OK) return cv;
    itb_status_t sv = validate_chunk_size(chunk_size);
    if (sv != ITB_OK) return sv;
    return decrypt_loop_single(noise, data, start,
                               read_fn, read_user_ctx,
                               write_fn, write_user_ctx,
                               chunk_size);
}

itb_status_t itb_stream_encrypt_triple(const itb_seed_t *noise,
                                       const itb_seed_t *data1,
                                       const itb_seed_t *data2,
                                       const itb_seed_t *data3,
                                       const itb_seed_t *start1,
                                       const itb_seed_t *start2,
                                       const itb_seed_t *start3,
                                       itb_stream_read_fn read_fn,
                                       void *read_user_ctx,
                                       itb_stream_write_fn write_fn,
                                       void *write_user_ctx,
                                       size_t chunk_size)
{
    if (noise == NULL || data1 == NULL || data2 == NULL || data3 == NULL ||
        start1 == NULL || start2 == NULL || start3 == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "one of the seven seeds is NULL");
    }
    itb_status_t cv = validate_callbacks(read_fn, write_fn);
    if (cv != ITB_OK) return cv;
    itb_status_t sv = validate_chunk_size(chunk_size);
    if (sv != ITB_OK) return sv;
    return encrypt_loop_triple(noise, data1, data2, data3,
                               start1, start2, start3,
                               read_fn, read_user_ctx,
                               write_fn, write_user_ctx,
                               chunk_size);
}

itb_status_t itb_stream_decrypt_triple(const itb_seed_t *noise,
                                       const itb_seed_t *data1,
                                       const itb_seed_t *data2,
                                       const itb_seed_t *data3,
                                       const itb_seed_t *start1,
                                       const itb_seed_t *start2,
                                       const itb_seed_t *start3,
                                       itb_stream_read_fn read_fn,
                                       void *read_user_ctx,
                                       itb_stream_write_fn write_fn,
                                       void *write_user_ctx,
                                       size_t chunk_size)
{
    if (noise == NULL || data1 == NULL || data2 == NULL || data3 == NULL ||
        start1 == NULL || start2 == NULL || start3 == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "one of the seven seeds is NULL");
    }
    itb_status_t cv = validate_callbacks(read_fn, write_fn);
    if (cv != ITB_OK) return cv;
    itb_status_t sv = validate_chunk_size(chunk_size);
    if (sv != ITB_OK) return sv;
    return decrypt_loop_triple(noise, data1, data2, data3,
                               start1, start2, start3,
                               read_fn, read_user_ctx,
                               write_fn, write_user_ctx,
                               chunk_size);
}

/* ------------------------------------------------------------------ */
/* Streaming AEAD — shared helpers                                     */
/* ------------------------------------------------------------------ */

#define ITB_STREAM_ID_LEN ((size_t) 32)

/*
 * Discovers the seed's native hash width (128 / 256 / 512). Used by
 * the auth-stream dispatcher to route per-chunk calls through the
 * matching ITB_*StreamAuthenticated* ABI export. The ABI signature
 * returns the width as the function value and the structural status
 * via the trailing out-status pointer.
 */
static itb_status_t seed_hash_width(const itb_seed_t *s, int *out_width)
{
    int st = ITB_OK;
    int w = ITB_SeedWidth(s->handle, &st);
    if (st != ITB_OK) {
        return itb_internal_set_error(st);
    }
    *out_width = w;
    return ITB_OK;
}

/*
 * Generates a CSPRNG-fresh 32-byte Streaming AEAD anchor by piggybacking
 * on libitb's own CSPRNG: ITB_NewSeedFromComponents with hash_key=NULL
 * triggers a CSPRNG draw on the Go side, and ITB_GetSeedHashKey reads
 * back the 32-byte fixed key under the blake3 primitive. The seed
 * handle is freed before the function returns; only the 32 random
 * bytes survive.
 */
static itb_status_t generate_stream_id(uint8_t out[ITB_STREAM_ID_LEN])
{
    /* Eight nonzero placeholder components — values are immaterial: the
     * CSPRNG-generated hash key is what becomes the stream_id. */
    uint64_t comps[8];
    for (size_t i = 0; i < 8; i++) {
        comps[i] = (uint64_t) (i + 1);
    }
    uintptr_t h = 0;
    int rc = ITB_NewSeedFromComponents((char *) "blake3", comps, 8,
                                       NULL, 0, &h);
    if (rc != ITB_OK) {
        return itb_internal_set_error(rc);
    }
    size_t got = 0;
    rc = ITB_GetSeedHashKey(h, out, ITB_STREAM_ID_LEN, &got);
    int free_rc = ITB_FreeSeed(h);
    if (rc != ITB_OK) {
        return itb_internal_set_error(rc);
    }
    if (free_rc != ITB_OK) {
        return itb_internal_set_error(free_rc);
    }
    if (got != ITB_STREAM_ID_LEN) {
        return itb_internal_set_error_msg(
            ITB_INTERNAL, "stream_id CSPRNG draw returned wrong byte count");
    }
    return ITB_OK;
}

/* Reads two big-endian bytes from `p` and returns them as size_t. */
static size_t read_be16(const uint8_t *p)
{
    return ((size_t) p[0] << 8) | (size_t) p[1];
}

/*
 * Inspects a chunk header sitting at the front of the auth-stream
 * accumulator and returns the chunk's pixel count (W * H) plus the
 * total chunk byte length. The chunk header layout is identical
 * across plain and authenticated streams: nonce (N bytes) || W (2
 * bytes BE) || H (2 bytes BE).
 */
static itb_status_t inspect_auth_chunk(const uint8_t *buf, size_t buf_len,
                                       size_t header_size,
                                       size_t *out_chunk_len,
                                       uint64_t *out_pixels)
{
    if (buf_len < header_size) {
        return ITB_BUFFER_TOO_SMALL; /* internal sentinel — caller waits for more */
    }
    /* Per-encryptor: chunk_len computed from caller-supplied header_size,
     * no process-global lookup. The auth-stream caller derives header_size
     * via ITB_Easy_HeaderSize(handle), which honours per-encryptor nonce
     * bits; routing through the global itb_parse_chunk_len would re-read
     * ITB_GetNonceBits and silently diverge from the per-instance value.
     * The W/H validation predicates below mirror capi.ParseChunkLen. */
    size_t w = read_be16(buf + header_size - 4);
    size_t h = read_be16(buf + header_size - 2);
    if (w == 0 || h == 0) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "auth stream: zero chunk dimensions");
    }
    if (w > (SIZE_MAX / h)) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "auth stream: chunk dimensions overflow");
    }
    size_t total_pixels = w * h;
    /* ITB_Channels() is a read-only constant (capi.Channels = itb.Channels = 8);
     * no global mutation path can change the value at runtime. */
    int channels = ITB_Channels();
    if ((size_t) channels == 0 ||
        total_pixels > (SIZE_MAX / (size_t) channels)) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "auth stream: chunk pixel count overflow");
    }
    /* Mirror the maxTotalPixels cap from capi.ParseChunkLen. */
    if (total_pixels > 10000000u) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "auth stream: chunk pixel count exceeds cap");
    }
    size_t chunk_len = header_size + total_pixels * (size_t) channels;
    if (chunk_len == 0) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "auth stream: zero-length chunk header");
    }
    *out_chunk_len = chunk_len;
    *out_pixels = (uint64_t) total_pixels;
    return ITB_OK;
}

/*
 * Per-chunk dispatch shapes for the four ITB_*StreamAuthenticated*
 * families.
 */
typedef int (*fn_enc_auth_single_t)(uintptr_t, uintptr_t, uintptr_t, uintptr_t,
                                    void *, size_t,
                                    uint8_t *, uint64_t, int,
                                    void *, size_t, size_t *);

typedef int (*fn_dec_auth_single_t)(uintptr_t, uintptr_t, uintptr_t, uintptr_t,
                                    void *, size_t,
                                    uint8_t *, uint64_t,
                                    void *, size_t, size_t *, int *);

typedef int (*fn_enc_auth_triple_t)(uintptr_t,
                                    uintptr_t, uintptr_t, uintptr_t,
                                    uintptr_t, uintptr_t, uintptr_t,
                                    uintptr_t,
                                    void *, size_t,
                                    uint8_t *, uint64_t, int,
                                    void *, size_t, size_t *);

typedef int (*fn_dec_auth_triple_t)(uintptr_t,
                                    uintptr_t, uintptr_t, uintptr_t,
                                    uintptr_t, uintptr_t, uintptr_t,
                                    uintptr_t,
                                    void *, size_t,
                                    uint8_t *, uint64_t,
                                    void *, size_t, size_t *, int *);

/* Dispatches the encrypt-side per-chunk call by hash width and emits
 * the resulting ciphertext via write_fn. Allocates / frees a fresh
 * output buffer on every call. */
static itb_status_t emit_chunk_auth_single(int width,
                                           const itb_seed_t *noise,
                                           const itb_seed_t *data,
                                           const itb_seed_t *start,
                                           const itb_mac_t *mac,
                                           const uint8_t *plaintext,
                                           size_t pt_len,
                                           uint8_t stream_id[ITB_STREAM_ID_LEN],
                                           uint64_t cum_pixels,
                                           int final_flag,
                                           itb_stream_write_fn write_fn,
                                           void *write_ctx)
{
    fn_enc_auth_single_t fn = NULL;
    switch (width) {
        case 128: fn = ITB_EncryptStreamAuthenticated128; break;
        case 256: fn = ITB_EncryptStreamAuthenticated256; break;
        case 512: fn = ITB_EncryptStreamAuthenticated512; break;
        default:
            return itb_internal_set_error_msg(
                ITB_SEED_WIDTH_MIX, "unsupported native hash width");
    }

    void *in_ptr = (pt_len == 0) ? NULL : (void *) plaintext;

    /* Pre-allocate from the saturating 1.25x + 128 KiB upper bound and
     * call once. The C ABI runs the full crypto on every call regardless
     * of out-buffer capacity; skipping the probe halves the per-chunk
     * cost on the steady-state path. The retry-once branch on
     * STATUS_BUFFER_TOO_SMALL preserves the safety net for combinations
     * outside the measured expansion-ratio matrix. */
    size_t cap = itb_internal_buf_cap(pt_len);
    uint8_t *ct = (uint8_t *) malloc(cap);
    if (ct == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }
    size_t written = 0;
    int rc = fn(noise->handle, data->handle, start->handle, mac->handle,
                in_ptr, pt_len,
                stream_id, cum_pixels, final_flag,
                ct, cap, &written);
    if (rc == ITB_BUFFER_TOO_SMALL) {
        size_t need = written;
        if (need == 0) {
            free(ct);
            return itb_internal_set_error_msg(
                ITB_INTERNAL, "BUFFER_TOO_SMALL with zero need");
        }
        uint8_t *resized = (uint8_t *) realloc(ct, need);
        if (resized == NULL) {
            free(ct);
            return itb_internal_set_error_msg(ITB_INTERNAL, "realloc failed");
        }
        ct = resized;
        cap = need;
        rc = fn(noise->handle, data->handle, start->handle, mac->handle,
                in_ptr, pt_len,
                stream_id, cum_pixels, final_flag,
                ct, cap, &written);
    }
    if (rc != ITB_OK) {
        free(ct);
        return itb_internal_set_error(rc);
    }
    if (written == 0) {
        free(ct);
        return ITB_OK;
    }
    int wrc = write_fn(write_ctx, ct, written);
    if (wrc != 0) {
        memset(ct, 0, written);
        free(ct);
        return io_write_error(wrc);
    }
    memset(ct, 0, written);
    free(ct);
    return ITB_OK;
}

static itb_status_t emit_chunk_auth_triple(int width,
                                           const itb_seed_t *noise,
                                           const itb_seed_t *data1,
                                           const itb_seed_t *data2,
                                           const itb_seed_t *data3,
                                           const itb_seed_t *start1,
                                           const itb_seed_t *start2,
                                           const itb_seed_t *start3,
                                           const itb_mac_t *mac,
                                           const uint8_t *plaintext,
                                           size_t pt_len,
                                           uint8_t stream_id[ITB_STREAM_ID_LEN],
                                           uint64_t cum_pixels,
                                           int final_flag,
                                           itb_stream_write_fn write_fn,
                                           void *write_ctx)
{
    fn_enc_auth_triple_t fn = NULL;
    switch (width) {
        case 128: fn = ITB_EncryptStreamAuthenticated3x128; break;
        case 256: fn = ITB_EncryptStreamAuthenticated3x256; break;
        case 512: fn = ITB_EncryptStreamAuthenticated3x512; break;
        default:
            return itb_internal_set_error_msg(
                ITB_SEED_WIDTH_MIX, "unsupported native hash width");
    }

    void *in_ptr = (pt_len == 0) ? NULL : (void *) plaintext;

    size_t cap = itb_internal_buf_cap(pt_len);
    uint8_t *ct = (uint8_t *) malloc(cap);
    if (ct == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }
    size_t written = 0;
    int rc = fn(noise->handle,
                data1->handle, data2->handle, data3->handle,
                start1->handle, start2->handle, start3->handle,
                mac->handle, in_ptr, pt_len,
                stream_id, cum_pixels, final_flag,
                ct, cap, &written);
    if (rc == ITB_BUFFER_TOO_SMALL) {
        size_t need = written;
        if (need == 0) {
            free(ct);
            return itb_internal_set_error_msg(
                ITB_INTERNAL, "BUFFER_TOO_SMALL with zero need");
        }
        uint8_t *resized = (uint8_t *) realloc(ct, need);
        if (resized == NULL) {
            free(ct);
            return itb_internal_set_error_msg(ITB_INTERNAL, "realloc failed");
        }
        ct = resized;
        cap = need;
        rc = fn(noise->handle,
                data1->handle, data2->handle, data3->handle,
                start1->handle, start2->handle, start3->handle,
                mac->handle, in_ptr, pt_len,
                stream_id, cum_pixels, final_flag,
                ct, cap, &written);
    }
    if (rc != ITB_OK) {
        free(ct);
        return itb_internal_set_error(rc);
    }
    if (written == 0) {
        free(ct);
        return ITB_OK;
    }
    int wrc = write_fn(write_ctx, ct, written);
    if (wrc != 0) {
        memset(ct, 0, written);
        free(ct);
        return io_write_error(wrc);
    }
    memset(ct, 0, written);
    free(ct);
    return ITB_OK;
}

/* Dispatches the decrypt-side per-chunk call by hash width and emits
 * the recovered plaintext via write_fn. *out_final_flag receives the
 * recovered terminator byte (0 / 1). */
static itb_status_t consume_chunk_auth_single(int width,
                                              const itb_seed_t *noise,
                                              const itb_seed_t *data,
                                              const itb_seed_t *start,
                                              const itb_mac_t *mac,
                                              const uint8_t *ciphertext,
                                              size_t ct_len,
                                              uint8_t stream_id[ITB_STREAM_ID_LEN],
                                              uint64_t cum_pixels,
                                              itb_stream_write_fn write_fn,
                                              void *write_ctx,
                                              int *out_final_flag)
{
    fn_dec_auth_single_t fn = NULL;
    switch (width) {
        case 128: fn = ITB_DecryptStreamAuthenticated128; break;
        case 256: fn = ITB_DecryptStreamAuthenticated256; break;
        case 512: fn = ITB_DecryptStreamAuthenticated512; break;
        default:
            return itb_internal_set_error_msg(
                ITB_SEED_WIDTH_MIX, "unsupported native hash width");
    }

    void *in_ptr = (ct_len == 0) ? NULL : (void *) ciphertext;
    int ff = 0;

    /* Pre-allocate from the saturating 1.25x + 128 KiB upper bound
     * sized on ct_len (decrypt-side plaintext is bounded above by the
     * incoming chunk size). One call on the steady-state path; retry
     * once on STATUS_BUFFER_TOO_SMALL covers any expansion-ratio
     * anomaly outside the measured matrix. */
    size_t cap = itb_internal_buf_cap(ct_len);
    uint8_t *pt = (uint8_t *) malloc(cap);
    if (pt == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }
    size_t written = 0;
    int rc = fn(noise->handle, data->handle, start->handle, mac->handle,
                in_ptr, ct_len,
                stream_id, cum_pixels,
                pt, cap, &written, &ff);
    if (rc == ITB_BUFFER_TOO_SMALL) {
        size_t need = written;
        if (need == 0) {
            memset(pt, 0, cap);
            free(pt);
            return itb_internal_set_error_msg(
                ITB_INTERNAL, "BUFFER_TOO_SMALL with zero need");
        }
        memset(pt, 0, cap);
        uint8_t *resized = (uint8_t *) realloc(pt, need);
        if (resized == NULL) {
            free(pt);
            return itb_internal_set_error_msg(ITB_INTERNAL, "realloc failed");
        }
        pt = resized;
        cap = need;
        rc = fn(noise->handle, data->handle, start->handle, mac->handle,
                in_ptr, ct_len,
                stream_id, cum_pixels,
                pt, cap, &written, &ff);
    }
    if (rc != ITB_OK) {
        memset(pt, 0, cap);
        free(pt);
        return itb_internal_set_error(rc);
    }
    if (written == 0) {
        free(pt);
        *out_final_flag = ff;
        return ITB_OK;
    }
    int wrc = write_fn(write_ctx, pt, written);
    if (wrc != 0) {
        memset(pt, 0, written);
        free(pt);
        return io_write_error(wrc);
    }
    memset(pt, 0, written);
    free(pt);
    *out_final_flag = ff;
    return ITB_OK;
}

static itb_status_t consume_chunk_auth_triple(int width,
                                              const itb_seed_t *noise,
                                              const itb_seed_t *data1,
                                              const itb_seed_t *data2,
                                              const itb_seed_t *data3,
                                              const itb_seed_t *start1,
                                              const itb_seed_t *start2,
                                              const itb_seed_t *start3,
                                              const itb_mac_t *mac,
                                              const uint8_t *ciphertext,
                                              size_t ct_len,
                                              uint8_t stream_id[ITB_STREAM_ID_LEN],
                                              uint64_t cum_pixels,
                                              itb_stream_write_fn write_fn,
                                              void *write_ctx,
                                              int *out_final_flag)
{
    fn_dec_auth_triple_t fn = NULL;
    switch (width) {
        case 128: fn = ITB_DecryptStreamAuthenticated3x128; break;
        case 256: fn = ITB_DecryptStreamAuthenticated3x256; break;
        case 512: fn = ITB_DecryptStreamAuthenticated3x512; break;
        default:
            return itb_internal_set_error_msg(
                ITB_SEED_WIDTH_MIX, "unsupported native hash width");
    }

    void *in_ptr = (ct_len == 0) ? NULL : (void *) ciphertext;
    int ff = 0;

    size_t cap = itb_internal_buf_cap(ct_len);
    uint8_t *pt = (uint8_t *) malloc(cap);
    if (pt == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }
    size_t written = 0;
    int rc = fn(noise->handle,
                data1->handle, data2->handle, data3->handle,
                start1->handle, start2->handle, start3->handle,
                mac->handle, in_ptr, ct_len,
                stream_id, cum_pixels,
                pt, cap, &written, &ff);
    if (rc == ITB_BUFFER_TOO_SMALL) {
        size_t need = written;
        if (need == 0) {
            memset(pt, 0, cap);
            free(pt);
            return itb_internal_set_error_msg(
                ITB_INTERNAL, "BUFFER_TOO_SMALL with zero need");
        }
        memset(pt, 0, cap);
        uint8_t *resized = (uint8_t *) realloc(pt, need);
        if (resized == NULL) {
            free(pt);
            return itb_internal_set_error_msg(ITB_INTERNAL, "realloc failed");
        }
        pt = resized;
        cap = need;
        rc = fn(noise->handle,
                data1->handle, data2->handle, data3->handle,
                start1->handle, start2->handle, start3->handle,
                mac->handle, in_ptr, ct_len,
                stream_id, cum_pixels,
                pt, cap, &written, &ff);
    }
    if (rc != ITB_OK) {
        memset(pt, 0, cap);
        free(pt);
        return itb_internal_set_error(rc);
    }
    if (written == 0) {
        free(pt);
        *out_final_flag = ff;
        return ITB_OK;
    }
    int wrc = write_fn(write_ctx, pt, written);
    if (wrc != 0) {
        memset(pt, 0, written);
        free(pt);
        return io_write_error(wrc);
    }
    memset(pt, 0, written);
    free(pt);
    *out_final_flag = ff;
    return ITB_OK;
}

/* ------------------------------------------------------------------ */
/* Streaming AEAD — encrypt loops                                       */
/* ------------------------------------------------------------------ */

/* Header-capturing write wrapper: reads the chunk's W * H from the
 * first `header_size` bytes of every chunk, accumulates the running
 * pixel sum into *cum, then forwards the bytes to the inner write
 * callback unchanged. */
struct cumctx {
    itb_stream_write_fn inner;
    void *inner_ctx;
    uint64_t cum_emitted;     /* sum of W*H over chunks already emitted */
    size_t   header_size;
    /* Accumulator for partial header bytes — the inner cipher may
     * call write_fn once with the whole chunk or multiple times for
     * different segments. The chunk wire layout always starts with
     * the header at offset 0 of the chunk, so the wrapper buffers
     * the first `header_size` bytes per chunk before parsing them. */
    uint8_t  hdr_buf[128];
    size_t   hdr_have;
    int      hdr_done;        /* 0 until the current chunk's header is parsed */
};

static int cum_write_fn(void *ctx, const void *buf, size_t n)
{
    struct cumctx *c = (struct cumctx *) ctx;
    const uint8_t *p = (const uint8_t *) buf;
    if (!c->hdr_done) {
        size_t want = c->header_size - c->hdr_have;
        size_t take = (n < want) ? n : want;
        memcpy(c->hdr_buf + c->hdr_have, p, take);
        c->hdr_have += take;
        if (c->hdr_have == c->header_size) {
            size_t w = read_be16(c->hdr_buf + c->header_size - 4);
            size_t h = read_be16(c->hdr_buf + c->header_size - 2);
            c->cum_emitted += (uint64_t) w * (uint64_t) h;
            c->hdr_done = 1;
        }
    }
    return c->inner(c->inner_ctx, p, n) == 0 ? 0 : 1;
}

/* Resets the cum-tracking wrapper between chunks so the next chunk's
 * header is parsed afresh. */
static void cumctx_reset_chunk(struct cumctx *c)
{
    c->hdr_have = 0;
    c->hdr_done = 0;
}

/*
 * Cum-tracking encrypt loop. Buffers one chunk-worth of plaintext at
 * a time; when the buffer is full and there's MORE to read, emits the
 * buffered chunk under final_flag=0 with the running offset, then
 * starts the next chunk. On EOF, emits the residual (possibly empty)
 * with final_flag=1. This is the deferred-final pattern — the
 * decision "is this the last chunk" is taken at EOF time, when the
 * read_fn has already signalled end-of-stream.
 */
static itb_status_t encrypt_loop_auth_single(int width,
                                                const itb_seed_t *noise,
                                                const itb_seed_t *data,
                                                const itb_seed_t *start,
                                                const itb_mac_t *mac,
                                                itb_stream_read_fn read_fn,
                                                void *read_ctx,
                                                itb_stream_write_fn write_fn,
                                                void *write_ctx,
                                                size_t chunk_size)
{
    uint8_t stream_id[ITB_STREAM_ID_LEN];
    itb_status_t st = generate_stream_id(stream_id);
    if (st != ITB_OK) return st;

    int hsz_int = itb_header_size();
    if (hsz_int <= 0 || (size_t) hsz_int > sizeof(((struct cumctx *) 0)->hdr_buf)) {
        return itb_internal_set_error_msg(
            ITB_INTERNAL, "header_size out of expected range");
    }

    int wrc = write_fn(write_ctx, stream_id, ITB_STREAM_ID_LEN);
    if (wrc != 0) return io_write_error(wrc);

    struct cumctx cum = {
        .inner = write_fn,
        .inner_ctx = write_ctx,
        .cum_emitted = 0,
        .header_size = (size_t) hsz_int,
        .hdr_have = 0,
        .hdr_done = 0,
    };

    uint8_t *cur = (uint8_t *) malloc(chunk_size);
    if (cur == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }
    size_t cur_len = 0;
    int eof = 0;

    /* Deferred-final pattern: read into `cur`. When `cur` is full,
     * peek-read 1 byte to see if more is coming. If yes, emit `cur`
     * as non-terminal then drain into a fresh `cur` starting from the
     * peeked byte. If no, emit `cur` as terminal and stop. */
    while (!eof) {
        /* Drain into cur until full or EOF. */
        while (cur_len < chunk_size && !eof) {
            size_t got = 0;
            int rrc = read_fn(read_ctx, cur + cur_len,
                              chunk_size - cur_len, &got);
            if (rrc != 0) {
                memset(cur, 0, chunk_size);
                free(cur);
                return io_read_error(rrc);
            }
            if (got == 0) {
                eof = 1;
                break;
            }
            cur_len += got;
        }

        /* `cur` is either chunk_size (drained to capacity) or
         * partially filled with EOF observed. Peek to decide
         * terminal. If full, attempt one byte of look-ahead. */
        int is_final = 0;
        uint8_t peek_byte = 0;
        size_t peek_got = 0;
        if (cur_len == chunk_size && !eof) {
            int rrc = read_fn(read_ctx, &peek_byte, 1, &peek_got);
            if (rrc != 0) {
                memset(cur, 0, chunk_size);
                free(cur);
                return io_read_error(rrc);
            }
            if (peek_got == 0) {
                eof = 1;
                is_final = 1;
            }
        } else {
            /* cur_len < chunk_size and eof — this IS the final
             * chunk. */
            is_final = 1;
        }

        cumctx_reset_chunk(&cum);
        st = emit_chunk_auth_single(
            width, noise, data, start, mac,
            cur, cur_len,
            stream_id, cum.cum_emitted, is_final,
            cum_write_fn, &cum);
        if (st != ITB_OK) {
            memset(cur, 0, chunk_size);
            free(cur);
            return st;
        }
        memset(cur, 0, chunk_size);
        cur_len = 0;

        if (is_final) {
            free(cur);
            itb_internal_reset_error();
            return ITB_OK;
        }
        /* peek_byte holds the first byte of the next chunk. */
        cur[0] = peek_byte;
        cur_len = 1;
    }

    /* Edge case: empty stream — no body bytes ever read, eof = 1,
     * loop never ran is_final=1. Emit a single terminating empty
     * chunk. */
    cumctx_reset_chunk(&cum);
    st = emit_chunk_auth_single(
        width, noise, data, start, mac,
        cur, 0,
        stream_id, cum.cum_emitted, 1,
        cum_write_fn, &cum);
    free(cur);
    if (st != ITB_OK) return st;
    itb_internal_reset_error();
    return ITB_OK;
}

static itb_status_t encrypt_loop_auth_triple(int width,
                                                const itb_seed_t *noise,
                                                const itb_seed_t *data1,
                                                const itb_seed_t *data2,
                                                const itb_seed_t *data3,
                                                const itb_seed_t *start1,
                                                const itb_seed_t *start2,
                                                const itb_seed_t *start3,
                                                const itb_mac_t *mac,
                                                itb_stream_read_fn read_fn,
                                                void *read_ctx,
                                                itb_stream_write_fn write_fn,
                                                void *write_ctx,
                                                size_t chunk_size)
{
    uint8_t stream_id[ITB_STREAM_ID_LEN];
    itb_status_t st = generate_stream_id(stream_id);
    if (st != ITB_OK) return st;

    int hsz_int = itb_header_size();
    if (hsz_int <= 0 || (size_t) hsz_int > sizeof(((struct cumctx *) 0)->hdr_buf)) {
        return itb_internal_set_error_msg(
            ITB_INTERNAL, "header_size out of expected range");
    }

    int wrc = write_fn(write_ctx, stream_id, ITB_STREAM_ID_LEN);
    if (wrc != 0) return io_write_error(wrc);

    struct cumctx cum = {
        .inner = write_fn,
        .inner_ctx = write_ctx,
        .cum_emitted = 0,
        .header_size = (size_t) hsz_int,
        .hdr_have = 0,
        .hdr_done = 0,
    };

    uint8_t *cur = (uint8_t *) malloc(chunk_size);
    if (cur == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }
    size_t cur_len = 0;
    int eof = 0;

    while (!eof) {
        while (cur_len < chunk_size && !eof) {
            size_t got = 0;
            int rrc = read_fn(read_ctx, cur + cur_len,
                              chunk_size - cur_len, &got);
            if (rrc != 0) {
                memset(cur, 0, chunk_size);
                free(cur);
                return io_read_error(rrc);
            }
            if (got == 0) {
                eof = 1;
                break;
            }
            cur_len += got;
        }

        int is_final = 0;
        uint8_t peek_byte = 0;
        size_t peek_got = 0;
        if (cur_len == chunk_size && !eof) {
            int rrc = read_fn(read_ctx, &peek_byte, 1, &peek_got);
            if (rrc != 0) {
                memset(cur, 0, chunk_size);
                free(cur);
                return io_read_error(rrc);
            }
            if (peek_got == 0) {
                eof = 1;
                is_final = 1;
            }
        } else {
            is_final = 1;
        }

        cumctx_reset_chunk(&cum);
        st = emit_chunk_auth_triple(
            width, noise, data1, data2, data3, start1, start2, start3,
            mac, cur, cur_len,
            stream_id, cum.cum_emitted, is_final,
            cum_write_fn, &cum);
        if (st != ITB_OK) {
            memset(cur, 0, chunk_size);
            free(cur);
            return st;
        }
        memset(cur, 0, chunk_size);
        cur_len = 0;

        if (is_final) {
            free(cur);
            itb_internal_reset_error();
            return ITB_OK;
        }
        cur[0] = peek_byte;
        cur_len = 1;
    }

    cumctx_reset_chunk(&cum);
    st = emit_chunk_auth_triple(
        width, noise, data1, data2, data3, start1, start2, start3,
        mac, cur, 0,
        stream_id, cum.cum_emitted, 1,
        cum_write_fn, &cum);
    free(cur);
    if (st != ITB_OK) return st;
    itb_internal_reset_error();
    return ITB_OK;
}

/* ------------------------------------------------------------------ */
/* Streaming AEAD — decrypt loops                                       */
/* ------------------------------------------------------------------ */

/*
 * Drains read_fn and feeds chunks into the per-chunk decrypt path.
 * Reads the 32-byte stream_id wire prefix once at start. Tracks the
 * running cumulative pixel offset by reading W and H from each
 * chunk's header before calling the decrypt ABI.
 *
 * Returns ITB_STREAM_TRUNCATED if EOF is reached without observing a
 * chunk whose recovered final_flag is 1. Returns ITB_STREAM_AFTER_FINAL
 * if extra chunk bytes follow the terminating chunk. ITB_MAC_FAILURE
 * surfaces verbatim from the per-chunk ABI on tampered transcript.
 */
static itb_status_t decrypt_loop_auth_single(int width,
                                             const itb_seed_t *noise,
                                             const itb_seed_t *data,
                                             const itb_seed_t *start,
                                             const itb_mac_t *mac,
                                             itb_stream_read_fn read_fn,
                                             void *read_ctx,
                                             itb_stream_write_fn write_fn,
                                             void *write_ctx,
                                             size_t chunk_size)
{
    int hsz_int = itb_header_size();
    if (hsz_int <= 0) {
        return itb_internal_set_error_msg(
            ITB_INTERNAL, "itb_header_size returned non-positive value");
    }
    size_t header_size = (size_t) hsz_int;

    uint8_t *accum = NULL;
    size_t accum_cap = 0;
    size_t accum_len = 0;

    uint8_t *read_buf = (uint8_t *) malloc(chunk_size);
    if (read_buf == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }

    uint8_t stream_id[ITB_STREAM_ID_LEN];
    size_t sid_have = 0;
    uint64_t cumulative = 0;
    int seen_final = 0;

    for (;;) {
        size_t got = 0;
        int rrc = read_fn(read_ctx, read_buf, chunk_size, &got);
        if (rrc != 0) {
            free(read_buf);
            free(accum);
            return io_read_error(rrc);
        }
        if (got == 0) {
            /* EOF. Drain any whole chunk left in accum. */
            while (accum_len > 0 && !seen_final) {
                size_t cl = 0;
                uint64_t pixels = 0;
                itb_status_t cs = inspect_auth_chunk(accum, accum_len,
                                                    header_size, &cl, &pixels);
                if (cs == ITB_BUFFER_TOO_SMALL) {
                    /* Header incomplete — truncated. */
                    break;
                }
                if (cs != ITB_OK) {
                    free(read_buf);
                    free(accum);
                    return cs;
                }
                if (accum_len < cl) break; /* body incomplete — truncated */
                int ff = 0;
                cs = consume_chunk_auth_single(
                    width, noise, data, start, mac,
                    accum, cl, stream_id, cumulative,
                    write_fn, write_ctx, &ff);
                if (cs != ITB_OK) {
                    free(read_buf);
                    free(accum);
                    return cs;
                }
                cumulative += pixels;
                accum_consume(accum, &accum_len, cl);
                if (ff != 0) {
                    seen_final = 1;
                    if (accum_len > 0) {
                        free(read_buf);
                        free(accum);
                        return itb_internal_set_error_msg(
                            ITB_STREAM_AFTER_FINAL,
                            "auth stream: trailing bytes after terminator");
                    }
                }
            }
            free(read_buf);
            free(accum);
            if (sid_have < ITB_STREAM_ID_LEN) {
                /* EOF before the 32-byte stream_id prefix landed:
                 * the wire is malformed at the protocol level rather
                 * than truncated mid-transcript. Surface as BAD_INPUT
                 * so the caller distinguishes "no header" from "no
                 * terminator". */
                return itb_internal_set_error_msg(
                    ITB_BAD_INPUT,
                    "auth stream: EOF before 32-byte stream_id prefix");
            }
            if (!seen_final) {
                return itb_internal_set_error_msg(
                    ITB_STREAM_TRUNCATED,
                    "auth stream: terminator never observed");
            }
            itb_internal_reset_error();
            return ITB_OK;
        }

        /* Fill stream_id first if not yet captured. */
        size_t copy_off = 0;
        if (sid_have < ITB_STREAM_ID_LEN) {
            size_t need = ITB_STREAM_ID_LEN - sid_have;
            size_t take = (got < need) ? got : need;
            memcpy(stream_id + sid_have, read_buf, take);
            sid_have += take;
            copy_off = take;
            if (got == take && sid_have < ITB_STREAM_ID_LEN) {
                continue; /* next read_fn — still gathering prefix */
            }
        }

        /* Append the rest into the accumulator. */
        size_t append_n = got - copy_off;
        if (append_n > 0) {
            itb_status_t gst = accum_grow(&accum, &accum_cap,
                                          accum_len + append_n);
            if (gst != ITB_OK) {
                free(read_buf);
                free(accum);
                return gst;
            }
            assert(accum != NULL);
            memcpy(accum + accum_len, read_buf + copy_off, append_n);
            accum_len += append_n;
        }

        /* Drain whole chunks. */
        for (;;) {
            if (seen_final) {
                if (accum_len > 0) {
                    free(read_buf);
                    free(accum);
                    return itb_internal_set_error_msg(
                        ITB_STREAM_AFTER_FINAL,
                        "auth stream: trailing bytes after terminator");
                }
                break;
            }
            size_t cl = 0;
            uint64_t pixels = 0;
            itb_status_t cs = inspect_auth_chunk(accum, accum_len,
                                                header_size, &cl, &pixels);
            if (cs == ITB_BUFFER_TOO_SMALL) break;
            if (cs != ITB_OK) {
                free(read_buf);
                free(accum);
                return cs;
            }
            if (accum_len < cl) break;
            int ff = 0;
            cs = consume_chunk_auth_single(
                width, noise, data, start, mac,
                accum, cl, stream_id, cumulative,
                write_fn, write_ctx, &ff);
            if (cs != ITB_OK) {
                free(read_buf);
                free(accum);
                return cs;
            }
            cumulative += pixels;
            accum_consume(accum, &accum_len, cl);
            if (ff != 0) {
                seen_final = 1;
            }
        }
    }
}

static itb_status_t decrypt_loop_auth_triple(int width,
                                             const itb_seed_t *noise,
                                             const itb_seed_t *data1,
                                             const itb_seed_t *data2,
                                             const itb_seed_t *data3,
                                             const itb_seed_t *start1,
                                             const itb_seed_t *start2,
                                             const itb_seed_t *start3,
                                             const itb_mac_t *mac,
                                             itb_stream_read_fn read_fn,
                                             void *read_ctx,
                                             itb_stream_write_fn write_fn,
                                             void *write_ctx,
                                             size_t chunk_size)
{
    int hsz_int = itb_header_size();
    if (hsz_int <= 0) {
        return itb_internal_set_error_msg(
            ITB_INTERNAL, "itb_header_size returned non-positive value");
    }
    size_t header_size = (size_t) hsz_int;

    uint8_t *accum = NULL;
    size_t accum_cap = 0;
    size_t accum_len = 0;

    uint8_t *read_buf = (uint8_t *) malloc(chunk_size);
    if (read_buf == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }

    uint8_t stream_id[ITB_STREAM_ID_LEN];
    size_t sid_have = 0;
    uint64_t cumulative = 0;
    int seen_final = 0;

    for (;;) {
        size_t got = 0;
        int rrc = read_fn(read_ctx, read_buf, chunk_size, &got);
        if (rrc != 0) {
            free(read_buf);
            free(accum);
            return io_read_error(rrc);
        }
        if (got == 0) {
            while (accum_len > 0 && !seen_final) {
                size_t cl = 0;
                uint64_t pixels = 0;
                itb_status_t cs = inspect_auth_chunk(accum, accum_len,
                                                    header_size, &cl, &pixels);
                if (cs == ITB_BUFFER_TOO_SMALL) break;
                if (cs != ITB_OK) {
                    free(read_buf);
                    free(accum);
                    return cs;
                }
                if (accum_len < cl) break;
                int ff = 0;
                cs = consume_chunk_auth_triple(
                    width, noise, data1, data2, data3, start1, start2, start3,
                    mac, accum, cl, stream_id, cumulative,
                    write_fn, write_ctx, &ff);
                if (cs != ITB_OK) {
                    free(read_buf);
                    free(accum);
                    return cs;
                }
                cumulative += pixels;
                accum_consume(accum, &accum_len, cl);
                if (ff != 0) {
                    seen_final = 1;
                    if (accum_len > 0) {
                        free(read_buf);
                        free(accum);
                        return itb_internal_set_error_msg(
                            ITB_STREAM_AFTER_FINAL,
                            "auth stream: trailing bytes after terminator");
                    }
                }
            }
            free(read_buf);
            free(accum);
            if (sid_have < ITB_STREAM_ID_LEN) {
                /* EOF before the 32-byte stream_id prefix landed:
                 * the wire is malformed at the protocol level rather
                 * than truncated mid-transcript. */
                return itb_internal_set_error_msg(
                    ITB_BAD_INPUT,
                    "auth stream: EOF before 32-byte stream_id prefix");
            }
            if (!seen_final) {
                return itb_internal_set_error_msg(
                    ITB_STREAM_TRUNCATED,
                    "auth stream: terminator never observed");
            }
            itb_internal_reset_error();
            return ITB_OK;
        }

        size_t copy_off = 0;
        if (sid_have < ITB_STREAM_ID_LEN) {
            size_t need = ITB_STREAM_ID_LEN - sid_have;
            size_t take = (got < need) ? got : need;
            memcpy(stream_id + sid_have, read_buf, take);
            sid_have += take;
            copy_off = take;
            if (got == take && sid_have < ITB_STREAM_ID_LEN) {
                continue;
            }
        }

        size_t append_n = got - copy_off;
        if (append_n > 0) {
            itb_status_t gst = accum_grow(&accum, &accum_cap,
                                          accum_len + append_n);
            if (gst != ITB_OK) {
                free(read_buf);
                free(accum);
                return gst;
            }
            assert(accum != NULL);
            memcpy(accum + accum_len, read_buf + copy_off, append_n);
            accum_len += append_n;
        }

        for (;;) {
            if (seen_final) {
                if (accum_len > 0) {
                    free(read_buf);
                    free(accum);
                    return itb_internal_set_error_msg(
                        ITB_STREAM_AFTER_FINAL,
                        "auth stream: trailing bytes after terminator");
                }
                break;
            }
            size_t cl = 0;
            uint64_t pixels = 0;
            itb_status_t cs = inspect_auth_chunk(accum, accum_len,
                                                header_size, &cl, &pixels);
            if (cs == ITB_BUFFER_TOO_SMALL) break;
            if (cs != ITB_OK) {
                free(read_buf);
                free(accum);
                return cs;
            }
            if (accum_len < cl) break;
            int ff = 0;
            cs = consume_chunk_auth_triple(
                width, noise, data1, data2, data3, start1, start2, start3,
                mac, accum, cl, stream_id, cumulative,
                write_fn, write_ctx, &ff);
            if (cs != ITB_OK) {
                free(read_buf);
                free(accum);
                return cs;
            }
            cumulative += pixels;
            accum_consume(accum, &accum_len, cl);
            if (ff != 0) {
                seen_final = 1;
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* Streaming AEAD — public entry points                                 */
/* ------------------------------------------------------------------ */

itb_status_t itb_stream_encrypt_auth(const itb_seed_t *noise,
                                     const itb_seed_t *data,
                                     const itb_seed_t *start,
                                     const itb_mac_t *mac,
                                     itb_stream_read_fn read_fn, void *read_user_ctx,
                                     itb_stream_write_fn write_fn, void *write_user_ctx,
                                     size_t chunk_size)
{
    if (noise == NULL || data == NULL || start == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "noise/data/start seed is NULL");
    }
    if (mac == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "mac handle is NULL");
    }
    itb_status_t cv = validate_callbacks(read_fn, write_fn);
    if (cv != ITB_OK) return cv;
    itb_status_t sv = validate_chunk_size(chunk_size);
    if (sv != ITB_OK) return sv;
    int width = 0;
    itb_status_t ws = seed_hash_width(noise, &width);
    if (ws != ITB_OK) return ws;
    return encrypt_loop_auth_single(width, noise, data, start, mac,
                                       read_fn, read_user_ctx,
                                       write_fn, write_user_ctx, chunk_size);
}

itb_status_t itb_stream_decrypt_auth(const itb_seed_t *noise,
                                     const itb_seed_t *data,
                                     const itb_seed_t *start,
                                     const itb_mac_t *mac,
                                     itb_stream_read_fn read_fn, void *read_user_ctx,
                                     itb_stream_write_fn write_fn, void *write_user_ctx,
                                     size_t chunk_size)
{
    if (noise == NULL || data == NULL || start == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "noise/data/start seed is NULL");
    }
    if (mac == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "mac handle is NULL");
    }
    itb_status_t cv = validate_callbacks(read_fn, write_fn);
    if (cv != ITB_OK) return cv;
    itb_status_t sv = validate_chunk_size(chunk_size);
    if (sv != ITB_OK) return sv;
    int width = 0;
    itb_status_t ws = seed_hash_width(noise, &width);
    if (ws != ITB_OK) return ws;
    return decrypt_loop_auth_single(width, noise, data, start, mac,
                                    read_fn, read_user_ctx,
                                    write_fn, write_user_ctx, chunk_size);
}

itb_status_t itb_stream_encrypt_auth_triple(const itb_seed_t *noise,
                                            const itb_seed_t *data1,
                                            const itb_seed_t *data2,
                                            const itb_seed_t *data3,
                                            const itb_seed_t *start1,
                                            const itb_seed_t *start2,
                                            const itb_seed_t *start3,
                                            const itb_mac_t *mac,
                                            itb_stream_read_fn read_fn,
                                            void *read_user_ctx,
                                            itb_stream_write_fn write_fn,
                                            void *write_user_ctx,
                                            size_t chunk_size)
{
    if (noise == NULL || data1 == NULL || data2 == NULL || data3 == NULL ||
        start1 == NULL || start2 == NULL || start3 == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "one of the seven seeds is NULL");
    }
    if (mac == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "mac handle is NULL");
    }
    itb_status_t cv = validate_callbacks(read_fn, write_fn);
    if (cv != ITB_OK) return cv;
    itb_status_t sv = validate_chunk_size(chunk_size);
    if (sv != ITB_OK) return sv;
    int width = 0;
    itb_status_t ws = seed_hash_width(noise, &width);
    if (ws != ITB_OK) return ws;
    return encrypt_loop_auth_triple(width,
                                       noise, data1, data2, data3,
                                       start1, start2, start3, mac,
                                       read_fn, read_user_ctx,
                                       write_fn, write_user_ctx, chunk_size);
}

itb_status_t itb_stream_decrypt_auth_triple(const itb_seed_t *noise,
                                            const itb_seed_t *data1,
                                            const itb_seed_t *data2,
                                            const itb_seed_t *data3,
                                            const itb_seed_t *start1,
                                            const itb_seed_t *start2,
                                            const itb_seed_t *start3,
                                            const itb_mac_t *mac,
                                            itb_stream_read_fn read_fn,
                                            void *read_user_ctx,
                                            itb_stream_write_fn write_fn,
                                            void *write_user_ctx,
                                            size_t chunk_size)
{
    if (noise == NULL || data1 == NULL || data2 == NULL || data3 == NULL ||
        start1 == NULL || start2 == NULL || start3 == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "one of the seven seeds is NULL");
    }
    if (mac == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "mac handle is NULL");
    }
    itb_status_t cv = validate_callbacks(read_fn, write_fn);
    if (cv != ITB_OK) return cv;
    itb_status_t sv = validate_chunk_size(chunk_size);
    if (sv != ITB_OK) return sv;
    int width = 0;
    itb_status_t ws = seed_hash_width(noise, &width);
    if (ws != ITB_OK) return ws;
    return decrypt_loop_auth_triple(width,
                                    noise, data1, data2, data3,
                                    start1, start2, start3, mac,
                                    read_fn, read_user_ctx,
                                    write_fn, write_user_ctx, chunk_size);
}

/* ------------------------------------------------------------------ */
/* Encryptor-bound Streaming AEAD                                      */
/* ------------------------------------------------------------------ */

/* Closed-state preflight for the encryptor-bound Streaming AEAD
 * helpers. Mirrors the cipher-method preflight in encryptor.c and
 * lives in this file to keep the streams source self-contained for
 * the auth-stream surface. */
static itb_status_t encryptor_check_open(const itb_encryptor_t *e)
{
    if (e == NULL) {
        return itb_internal_set_error_msg(ITB_BAD_INPUT, "encryptor is NULL");
    }
    if (e->closed != 0 || e->handle == 0) {
        return itb_internal_set_error_msg(
            ITB_EASY_CLOSED, "encryptor has been closed");
    }
    return ITB_OK;
}

/* Wipe-on-grow cache router for the Easy AEAD streaming per-chunk
 * dispatchers. Mirrors encryptor.c::ensure_cache against the SAME
 * encryptor->out_cache field that cipher_call uses for Single Message
 * Easy encrypt / decrypt — the contract codifies cache reuse on
 * the per-chunk Easy AEAD path with the same scope as the Single Message
 * canonical reference. The cache stays internal as the FFI write
 * target ONLY; user code never observes the cache pointer
 * (aliasing-footgun mitigation — handled at the return path
 * via a fresh user_buf + memcpy + free, identical to cipher_call).
 *
 * Wipe-on-grow zeroes the previous cache contents before freeing, so
 * the most-recent chunk plaintext / ciphertext does not linger in heap
 * garbage. Wipe-on-close runs through encryptor.c::wipe_cache from
 * itb_encryptor_close / itb_encryptor_free; the streaming dispatcher
 * does not own the lifecycle. */
static itb_status_t stream_ensure_cache(struct itb_encryptor *e, size_t need)
{
    if (e->out_cache != NULL && e->out_cache_cap >= need) {
        return ITB_OK;
    }
    if (e->out_cache != NULL && e->out_cache_cap > 0) {
        memset(e->out_cache, 0, e->out_cache_cap);
        free(e->out_cache);
        e->out_cache = NULL;
        e->out_cache_cap = 0;
    }
    size_t cap = (need < 131072) ? 131072 : need;
    uint8_t *buf = (uint8_t *) malloc(cap);
    if (buf == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }
    e->out_cache = buf;
    e->out_cache_cap = cap;
    assert(e->out_cache != NULL);
    return ITB_OK;
}

/* Per-chunk encrypt dispatcher for the Easy Mode auth-stream surface.
 * Routes through ITB_Easy_EncryptStreamAuth and emits the produced
 * chunk wire bytes via write_fn (after passing through cum_write_fn
 * for the running-offset book-keeping).
 *
 * The FFI write target is the encryptor's internal out_cache, reused
 * across every chunk dispatched through the same encryptor — the
 * "Streaming AEAD per-chunk output buffer cache reuse" contract,
 * mirroring encryptor.c::cipher_call. After the FFI returns, a fresh
 * user-owned buffer is malloc'd and the bytes are memcpy'd from the
 * cache (aliasing-footgun mitigation — never hand the caller
 * a pointer into the cache); the user_buf is handed to write_fn and
 * freed once the synchronous callback returns. */
static itb_status_t emit_chunk_easy_auth(struct itb_encryptor *e,
                                         const uint8_t *plaintext,
                                         size_t pt_len,
                                         uint8_t stream_id[ITB_STREAM_ID_LEN],
                                         uint64_t cum_pixels,
                                         int final_flag,
                                         itb_stream_write_fn write_fn,
                                         void *write_ctx)
{
    void *in_ptr = (pt_len == 0) ? NULL : (void *) plaintext;
    size_t cap = itb_internal_buf_cap(pt_len);
    itb_status_t alloc_st = stream_ensure_cache(e, cap);
    if (alloc_st != ITB_OK) {
        return alloc_st;
    }
    size_t written = 0;
    int rc = ITB_Easy_EncryptStreamAuth(e->handle, in_ptr, pt_len,
                                        stream_id, cum_pixels, final_flag,
                                        e->out_cache, e->out_cache_cap,
                                        &written);
    if (rc == ITB_BUFFER_TOO_SMALL) {
        size_t need = written;
        if (need == 0) {
            return itb_internal_set_error_msg(
                ITB_INTERNAL, "BUFFER_TOO_SMALL with zero need");
        }
        alloc_st = stream_ensure_cache(e, need);
        if (alloc_st != ITB_OK) {
            return alloc_st;
        }
        rc = ITB_Easy_EncryptStreamAuth(e->handle, in_ptr, pt_len,
                                        stream_id, cum_pixels, final_flag,
                                        e->out_cache, e->out_cache_cap,
                                        &written);
    }
    if (rc != ITB_OK) {
        return itb_internal_set_error(rc);
    }
    if (written == 0) {
        return ITB_OK;
    }
    /* §11.o.2 aliasing-footgun mitigation: hand the caller a fresh
     * user-owned buffer rather than a pointer into the encryptor's
     * cache. The cache is reused across subsequent per-chunk dispatch
     * sites; a pointer-into-cache surfaced through write_fn could be
     * overwritten if the caller's sink retained the pointer past the
     * synchronous callback boundary. */
    uint8_t *user_buf = (uint8_t *) malloc(written);
    if (user_buf == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }
    memcpy(user_buf, e->out_cache, written);
    int wrc = write_fn(write_ctx, user_buf, written);
    if (wrc != 0) {
        memset(user_buf, 0, written);
        free(user_buf);
        return io_write_error(wrc);
    }
    memset(user_buf, 0, written);
    free(user_buf);
    return ITB_OK;
}

static itb_status_t consume_chunk_easy_auth(struct itb_encryptor *e,
                                            const uint8_t *ciphertext,
                                            size_t ct_len,
                                            uint8_t stream_id[ITB_STREAM_ID_LEN],
                                            uint64_t cum_pixels,
                                            itb_stream_write_fn write_fn,
                                            void *write_ctx,
                                            int *out_final_flag)
{
    void *in_ptr = (ct_len == 0) ? NULL : (void *) ciphertext;
    int ff = 0;
    size_t cap = itb_internal_buf_cap(ct_len);
    itb_status_t alloc_st = stream_ensure_cache(e, cap);
    if (alloc_st != ITB_OK) {
        return alloc_st;
    }
    size_t written = 0;
    int rc = ITB_Easy_DecryptStreamAuth(e->handle, in_ptr, ct_len,
                                        stream_id, cum_pixels,
                                        e->out_cache, e->out_cache_cap,
                                        &written, &ff);
    if (rc == ITB_BUFFER_TOO_SMALL) {
        size_t need = written;
        if (need == 0) {
            return itb_internal_set_error_msg(
                ITB_INTERNAL, "BUFFER_TOO_SMALL with zero need");
        }
        alloc_st = stream_ensure_cache(e, need);
        if (alloc_st != ITB_OK) {
            return alloc_st;
        }
        rc = ITB_Easy_DecryptStreamAuth(e->handle, in_ptr, ct_len,
                                        stream_id, cum_pixels,
                                        e->out_cache, e->out_cache_cap,
                                        &written, &ff);
    }
    if (rc != ITB_OK) {
        return itb_internal_set_error(rc);
    }
    if (written == 0) {
        *out_final_flag = ff;
        return ITB_OK;
    }
    /* §11.o.2 aliasing-footgun mitigation: fresh user-owned buffer
     * + memcpy from cache, mirroring the encrypt-side discipline above. */
    uint8_t *user_buf = (uint8_t *) malloc(written);
    if (user_buf == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }
    memcpy(user_buf, e->out_cache, written);
    int wrc = write_fn(write_ctx, user_buf, written);
    if (wrc != 0) {
        memset(user_buf, 0, written);
        free(user_buf);
        return io_write_error(wrc);
    }
    memset(user_buf, 0, written);
    free(user_buf);
    *out_final_flag = ff;
    return ITB_OK;
}

itb_status_t itb_encryptor_stream_encrypt_auth(itb_encryptor_t *e,
                                               itb_stream_read_fn read_fn,
                                               void *read_user_ctx,
                                               itb_stream_write_fn write_fn,
                                               void *write_user_ctx,
                                               size_t chunk_size)
{
    itb_status_t open_st = encryptor_check_open(e);
    if (open_st != ITB_OK) return open_st;
    itb_status_t cv = validate_callbacks(read_fn, write_fn);
    if (cv != ITB_OK) return cv;
    itb_status_t sv = validate_chunk_size(chunk_size);
    if (sv != ITB_OK) return sv;

    uint8_t stream_id[ITB_STREAM_ID_LEN];
    itb_status_t st = generate_stream_id(stream_id);
    if (st != ITB_OK) return st;

    int hsz_status = ITB_OK;
    int hsz_int = ITB_Easy_HeaderSize(e->handle, &hsz_status);
    if (hsz_status != ITB_OK) {
        return itb_internal_set_error(hsz_status);
    }
    if (hsz_int <= 0 || (size_t) hsz_int > sizeof(((struct cumctx *) 0)->hdr_buf)) {
        return itb_internal_set_error_msg(
            ITB_INTERNAL, "encryptor header_size out of expected range");
    }

    int wrc = write_fn(write_user_ctx, stream_id, ITB_STREAM_ID_LEN);
    if (wrc != 0) return io_write_error(wrc);

    struct cumctx cum = {
        .inner = write_fn,
        .inner_ctx = write_user_ctx,
        .cum_emitted = 0,
        .header_size = (size_t) hsz_int,
        .hdr_have = 0,
        .hdr_done = 0,
    };

    uint8_t *cur = (uint8_t *) malloc(chunk_size);
    if (cur == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }
    size_t cur_len = 0;
    int eof = 0;

    while (!eof) {
        while (cur_len < chunk_size && !eof) {
            size_t got = 0;
            int rrc = read_fn(read_user_ctx, cur + cur_len,
                              chunk_size - cur_len, &got);
            if (rrc != 0) {
                memset(cur, 0, chunk_size);
                free(cur);
                return io_read_error(rrc);
            }
            if (got == 0) {
                eof = 1;
                break;
            }
            cur_len += got;
        }

        int is_final = 0;
        uint8_t peek_byte = 0;
        size_t peek_got = 0;
        if (cur_len == chunk_size && !eof) {
            int rrc = read_fn(read_user_ctx, &peek_byte, 1, &peek_got);
            if (rrc != 0) {
                memset(cur, 0, chunk_size);
                free(cur);
                return io_read_error(rrc);
            }
            if (peek_got == 0) {
                eof = 1;
                is_final = 1;
            }
        } else {
            is_final = 1;
        }

        cumctx_reset_chunk(&cum);
        st = emit_chunk_easy_auth(e, cur, cur_len,
                                  stream_id, cum.cum_emitted, is_final,
                                  cum_write_fn, &cum);
        if (st != ITB_OK) {
            memset(cur, 0, chunk_size);
            free(cur);
            return st;
        }
        memset(cur, 0, chunk_size);
        cur_len = 0;

        if (is_final) {
            free(cur);
            itb_internal_reset_error();
            return ITB_OK;
        }
        cur[0] = peek_byte;
        cur_len = 1;
    }

    cumctx_reset_chunk(&cum);
    st = emit_chunk_easy_auth(e, cur, 0,
                              stream_id, cum.cum_emitted, 1,
                              cum_write_fn, &cum);
    free(cur);
    if (st != ITB_OK) return st;
    itb_internal_reset_error();
    return ITB_OK;
}

itb_status_t itb_encryptor_stream_decrypt_auth(itb_encryptor_t *e,
                                               itb_stream_read_fn read_fn,
                                               void *read_user_ctx,
                                               itb_stream_write_fn write_fn,
                                               void *write_user_ctx,
                                               size_t chunk_size)
{
    itb_status_t open_st = encryptor_check_open(e);
    if (open_st != ITB_OK) return open_st;
    itb_status_t cv = validate_callbacks(read_fn, write_fn);
    if (cv != ITB_OK) return cv;
    itb_status_t sv = validate_chunk_size(chunk_size);
    if (sv != ITB_OK) return sv;

    int hsz_status = ITB_OK;
    int hsz_int = ITB_Easy_HeaderSize(e->handle, &hsz_status);
    if (hsz_status != ITB_OK) {
        return itb_internal_set_error(hsz_status);
    }
    if (hsz_int <= 0) {
        return itb_internal_set_error_msg(
            ITB_INTERNAL, "encryptor header_size non-positive");
    }
    size_t header_size = (size_t) hsz_int;

    uint8_t *accum = NULL;
    size_t accum_cap = 0;
    size_t accum_len = 0;

    uint8_t *read_buf = (uint8_t *) malloc(chunk_size);
    if (read_buf == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }

    uint8_t stream_id[ITB_STREAM_ID_LEN];
    size_t sid_have = 0;
    uint64_t cumulative = 0;
    int seen_final = 0;

    for (;;) {
        size_t got = 0;
        int rrc = read_fn(read_user_ctx, read_buf, chunk_size, &got);
        if (rrc != 0) {
            free(read_buf);
            free(accum);
            return io_read_error(rrc);
        }
        if (got == 0) {
            while (accum_len > 0 && !seen_final) {
                size_t cl = 0;
                uint64_t pixels = 0;
                itb_status_t cs = inspect_auth_chunk(accum, accum_len,
                                                    header_size, &cl, &pixels);
                if (cs == ITB_BUFFER_TOO_SMALL) break;
                if (cs != ITB_OK) {
                    free(read_buf);
                    free(accum);
                    return cs;
                }
                if (accum_len < cl) break;
                int ff = 0;
                cs = consume_chunk_easy_auth(e, accum, cl,
                                             stream_id, cumulative,
                                             write_fn, write_user_ctx, &ff);
                if (cs != ITB_OK) {
                    free(read_buf);
                    free(accum);
                    return cs;
                }
                cumulative += pixels;
                accum_consume(accum, &accum_len, cl);
                if (ff != 0) {
                    seen_final = 1;
                    if (accum_len > 0) {
                        free(read_buf);
                        free(accum);
                        return itb_internal_set_error_msg(
                            ITB_STREAM_AFTER_FINAL,
                            "auth stream: trailing bytes after terminator");
                    }
                }
            }
            free(read_buf);
            free(accum);
            if (sid_have < ITB_STREAM_ID_LEN) {
                /* EOF before the 32-byte stream_id prefix landed:
                 * the wire is malformed at the protocol level rather
                 * than truncated mid-transcript. */
                return itb_internal_set_error_msg(
                    ITB_BAD_INPUT,
                    "auth stream: EOF before 32-byte stream_id prefix");
            }
            if (!seen_final) {
                return itb_internal_set_error_msg(
                    ITB_STREAM_TRUNCATED,
                    "auth stream: terminator never observed");
            }
            itb_internal_reset_error();
            return ITB_OK;
        }

        size_t copy_off = 0;
        if (sid_have < ITB_STREAM_ID_LEN) {
            size_t need = ITB_STREAM_ID_LEN - sid_have;
            size_t take = (got < need) ? got : need;
            memcpy(stream_id + sid_have, read_buf, take);
            sid_have += take;
            copy_off = take;
            if (got == take && sid_have < ITB_STREAM_ID_LEN) {
                continue;
            }
        }

        size_t append_n = got - copy_off;
        if (append_n > 0) {
            itb_status_t gst = accum_grow(&accum, &accum_cap,
                                          accum_len + append_n);
            if (gst != ITB_OK) {
                free(read_buf);
                free(accum);
                return gst;
            }
            assert(accum != NULL);
            memcpy(accum + accum_len, read_buf + copy_off, append_n);
            accum_len += append_n;
        }

        for (;;) {
            if (seen_final) {
                if (accum_len > 0) {
                    free(read_buf);
                    free(accum);
                    return itb_internal_set_error_msg(
                        ITB_STREAM_AFTER_FINAL,
                        "auth stream: trailing bytes after terminator");
                }
                break;
            }
            size_t cl = 0;
            uint64_t pixels = 0;
            itb_status_t cs = inspect_auth_chunk(accum, accum_len,
                                                header_size, &cl, &pixels);
            if (cs == ITB_BUFFER_TOO_SMALL) break;
            if (cs != ITB_OK) {
                free(read_buf);
                free(accum);
                return cs;
            }
            if (accum_len < cl) break;
            int ff = 0;
            cs = consume_chunk_easy_auth(e, accum, cl,
                                         stream_id, cumulative,
                                         write_fn, write_user_ctx, &ff);
            if (cs != ITB_OK) {
                free(read_buf);
                free(accum);
                return cs;
            }
            cumulative += pixels;
            accum_consume(accum, &accum_len, cl);
            if (ff != 0) {
                seen_final = 1;
            }
        }
    }
}
