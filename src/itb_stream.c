/*
 * itb_stream.c — incremental stream sessions over an open Pipeline
 * plus the whole-buffer pump conveniences.
 *
 * A session is a dumb byte pump: plaintext (or wire) goes in through
 * write, produced bytes come out through read. All chunking, MAC,
 * envelope, and wire-format decisions stay inside libitb — the
 * binding moves opaque bytes and relays status codes.
 */

#include <stdlib.h>
#include <string.h>

#include "internal.h"

/* ------------------------------------------------------------------ */
/* Session lifecycle                                                   */
/* ------------------------------------------------------------------ */

static itb_status stream_begin(const itb_pipeline *pipe, int encrypt,
                               itb_stream **out)
{
    if (out == NULL) {
        return ITB_STATUS_BAD_INPUT;
    }
    *out = NULL;
    if (pipe == NULL) {
        return ITB_STATUS_BAD_INPUT;
    }
    itb_stream *stream = calloc(1, sizeof(*stream));
    if (stream == NULL) {
        return ITB_STATUS_INTERNAL;
    }
    uintptr_t handle = 0;
    int rc = encrypt ? ITB_Triple_EncryptStreamBegin(pipe->handle, &handle)
                     : ITB_Triple_DecryptStreamBegin(pipe->handle, &handle);
    if (rc != (int)ITB_STATUS_OK) {
        free(stream);
        return itb_internal_status(rc);
    }
    stream->handle = handle;
    *out = stream;
    return ITB_STATUS_OK;
}

itb_status itb_pipeline_encrypt_stream_begin(const itb_pipeline *pipe,
                                             itb_stream **out)
{
    return stream_begin(pipe, 1, out);
}

itb_status itb_pipeline_decrypt_stream_begin(const itb_pipeline *pipe,
                                             itb_stream **out)
{
    return stream_begin(pipe, 0, out);
}

itb_status itb_stream_write(itb_stream *stream,
                            const uint8_t *src, size_t src_len)
{
    if (stream == NULL || (src == NULL && src_len > 0)) {
        return ITB_STATUS_BAD_INPUT;
    }
    return itb_internal_status(
        ITB_Triple_StreamWrite(stream->handle, (void *)src, src_len));
}

itb_status itb_stream_end(itb_stream *stream)
{
    if (stream == NULL) {
        return ITB_STATUS_BAD_INPUT;
    }
    return itb_internal_status(ITB_Triple_StreamEnd(stream->handle));
}

itb_status itb_stream_read(itb_stream *stream,
                           uint8_t *dst, size_t dst_cap,
                           size_t *n_read, int *finished)
{
    if (n_read == NULL || finished == NULL) {
        return ITB_STATUS_BAD_INPUT;
    }
    *n_read = 0;
    *finished = 0;
    if (stream == NULL || (dst == NULL && dst_cap > 0)) {
        return ITB_STATUS_BAD_INPUT;
    }
    int fin = 0;
    int rc = ITB_Triple_StreamRead(stream->handle, dst, dst_cap, n_read, &fin);
    if (rc != (int)ITB_STATUS_OK) {
        *n_read = 0;
        return itb_internal_status(rc);
    }
    *finished = fin != 0 ? 1 : 0;
    return ITB_STATUS_OK;
}

void itb_stream_free(itb_stream *stream)
{
    if (stream == NULL) {
        return;
    }
    if (stream->handle != 0) {
        /* StreamFree cancels and releases from any state, wiping the
         * Go-side spool; the status is deliberately ignored on the
         * release path. */
        (void)ITB_Triple_StreamFree(stream->handle);
        stream->handle = 0;
    }
    free(stream);
}

/* ------------------------------------------------------------------ */
/* Whole-buffer pumps                                                  */
/* ------------------------------------------------------------------ */

/* Growable output accumulator. */
struct acc {
    uint8_t *buf;
    size_t len;
    size_t cap;
};

static itb_status acc_append(struct acc *a, const uint8_t *src, size_t n)
{
    if (n == 0) {
        return ITB_STATUS_OK;
    }
    if (a->len + n < a->len) {
        return ITB_STATUS_INTERNAL; /* size_t overflow */
    }
    if (a->len + n > a->cap) {
        size_t cap = a->cap > 0 ? a->cap : ITB_PUMP_BUF;
        while (cap < a->len + n) {
            if (cap > (SIZE_MAX >> 1)) {
                return ITB_STATUS_INTERNAL;
            }
            cap *= 2;
        }
        uint8_t *grown = realloc(a->buf, cap);
        if (grown == NULL) {
            return ITB_STATUS_INTERNAL;
        }
        a->buf = grown;
        a->cap = cap;
    }
    memcpy(a->buf + a->len, src, n);
    a->len += n;
    return ITB_STATUS_OK;
}

/* Canonical pump: begin session → feed bounded slices, draining the
 * spool after each write → end → drain until finished → free. The
 * whole output lands in one malloc'd buffer handed to the caller. */
static itb_status pump(const itb_pipeline *pipe, int encrypt,
                       const uint8_t *src, size_t src_len,
                       uint8_t **out, size_t *out_len)
{
    if (out == NULL || out_len == NULL) {
        return ITB_STATUS_BAD_INPUT;
    }
    *out = NULL;
    *out_len = 0;
    if (pipe == NULL || (src == NULL && src_len > 0)) {
        return ITB_STATUS_BAD_INPUT;
    }

    itb_stream *stream = NULL;
    itb_status st = stream_begin(pipe, encrypt, &stream);
    if (st != ITB_STATUS_OK) {
        return st;
    }

    struct acc a = { NULL, 0, 0 };
    uint8_t *scratch = malloc(ITB_PUMP_BUF);
    if (scratch == NULL) {
        st = ITB_STATUS_INTERNAL;
        goto done;
    }

    size_t offset = 0;
    while (offset < src_len) {
        size_t slice = src_len - offset;
        if (slice > ITB_PUMP_BUF) {
            slice = ITB_PUMP_BUF;
        }
        st = itb_stream_write(stream, src + offset, slice);
        if (st != ITB_STATUS_OK) {
            goto done;
        }
        offset += slice;
        /* Drain whatever the chain has produced so far; a read before
         * end never blocks. */
        for (;;) {
            size_t n = 0;
            int fin = 0;
            st = itb_stream_read(stream, scratch, ITB_PUMP_BUF, &n, &fin);
            if (st != ITB_STATUS_OK) {
                goto done;
            }
            if (n == 0) {
                break;
            }
            st = acc_append(&a, scratch, n);
            if (st != ITB_STATUS_OK) {
                goto done;
            }
        }
    }

    st = itb_stream_end(stream);
    if (st != ITB_STATUS_OK) {
        goto done;
    }
    for (;;) {
        size_t n = 0;
        int fin = 0;
        st = itb_stream_read(stream, scratch, ITB_PUMP_BUF, &n, &fin);
        if (st != ITB_STATUS_OK) {
            goto done;
        }
        st = acc_append(&a, scratch, n);
        if (st != ITB_STATUS_OK) {
            goto done;
        }
        if (fin) {
            break;
        }
    }

done:
    free(scratch);
    itb_stream_free(stream);
    if (st != ITB_STATUS_OK) {
        free(a.buf);
        return st;
    }
    if (a.buf == NULL) {
        /* Zero-length output: hand back a real allocation so the
         * caller's itb_bytes_free contract stays uniform. */
        a.buf = malloc(1);
        if (a.buf == NULL) {
            return ITB_STATUS_INTERNAL;
        }
    }
    *out = a.buf;
    *out_len = a.len;
    return ITB_STATUS_OK;
}

itb_status itb_pipeline_encrypt_stream_pump(const itb_pipeline *pipe,
                                            const uint8_t *plain, size_t plain_len,
                                            uint8_t **wire_out, size_t *wire_len_out)
{
    return pump(pipe, 1, plain, plain_len, wire_out, wire_len_out);
}

itb_status itb_pipeline_decrypt_stream_pump(const itb_pipeline *pipe,
                                            const uint8_t *wire, size_t wire_len,
                                            uint8_t **plain_out, size_t *plain_len_out)
{
    return pump(pipe, 0, wire, wire_len, plain_out, plain_len_out);
}
