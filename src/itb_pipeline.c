/*
 * itb_pipeline.c — Triple Pipeline handle lifecycle plus the Single
 * Message cipher entries and profile registration.
 *
 * Binding-side logic is limited to the four FFI-boundary inversions:
 * caller-allocated buffers with the codified retry-once on
 * ITB_STATUS_BUFFER_TOO_SMALL, handle release glue, byte transport,
 * and status relay. Everything else — validation, profile catalogue,
 * wire format, MAC handling — is Go's job.
 */

#include <stdlib.h>
#include <string.h>

#include "internal.h"

size_t itb_internal_out_cap(size_t payload)
{
    const size_t floor_cap = 131072;
    size_t cap = payload + payload / 4;
    if (cap < payload || cap + floor_cap < cap) {
        return payload; /* overflow-adjacent sizes: exact payload */
    }
    cap += floor_cap;
    return cap > floor_cap ? cap : floor_cap;
}

/* ------------------------------------------------------------------ */
/* Init / Open / Free / accessors                                      */
/* ------------------------------------------------------------------ */

itb_status itb_pipeline_init(const char *profile, const itb_opts *opts,
                             itb_pipeline **out)
{
    if (out == NULL) {
        return ITB_STATUS_BAD_INPUT;
    }
    *out = NULL;
    if (profile == NULL) {
        return ITB_STATUS_BAD_INPUT;
    }
    itb_pipeline *pipe = calloc(1, sizeof(*pipe));
    if (pipe == NULL) {
        return ITB_STATUS_INTERNAL;
    }
    size_t cap = ITB_BLOB_CAP;
    uint8_t *blob = malloc(cap);
    if (blob == NULL) {
        free(pipe);
        return ITB_STATUS_INTERNAL;
    }
    size_t blob_len = 0;
    uintptr_t handle = 0;
    int rc = ITB_Triple_Init((char *)profile,
                             (char *)itb_internal_opts_cstr(opts),
                             blob, cap, &blob_len, &handle);
    if (rc == (int)ITB_STATUS_BUFFER_TOO_SMALL && blob_len > cap) {
        /* Go closed the undersized attempt; the retry re-runs Init
         * and yields a fresh session. */
        uint8_t *grown = realloc(blob, blob_len);
        if (grown == NULL) {
            free(blob);
            free(pipe);
            return ITB_STATUS_INTERNAL;
        }
        blob = grown;
        cap = blob_len;
        handle = 0;
        rc = ITB_Triple_Init((char *)profile,
                             (char *)itb_internal_opts_cstr(opts),
                             blob, cap, &blob_len, &handle);
    }
    if (rc != (int)ITB_STATUS_OK) {
        free(blob);
        free(pipe);
        return itb_internal_status(rc);
    }
    pipe->handle = handle;
    pipe->blob = blob;
    pipe->blob_len = blob_len;
    *out = pipe;
    return ITB_STATUS_OK;
}

itb_status itb_pipeline_open(const char *profile,
                             const uint8_t *blob, size_t blob_len,
                             const itb_opts *opts,
                             const uint8_t *perm_master, size_t perm_master_len,
                             const uint8_t *wrap_master, size_t wrap_master_len,
                             itb_pipeline **out)
{
    if (out == NULL) {
        return ITB_STATUS_BAD_INPUT;
    }
    *out = NULL;
    if (profile == NULL || blob == NULL || blob_len == 0) {
        return ITB_STATUS_BAD_INPUT;
    }
    int perm_given = perm_master != NULL && perm_master_len > 0;
    int wrap_given = wrap_master != NULL && wrap_master_len > 0;
    if (perm_given != wrap_given) {
        return ITB_STATUS_BAD_INPUT; /* half-supplied override pair */
    }
    size_t masters_count = perm_given ? 2 : 0;

    /* The Pipeline keeps its own copy of the blob for the accessor. */
    itb_pipeline *pipe = calloc(1, sizeof(*pipe));
    if (pipe == NULL) {
        return ITB_STATUS_INTERNAL;
    }
    uint8_t *blob_copy = malloc(blob_len);
    if (blob_copy == NULL) {
        free(pipe);
        return ITB_STATUS_INTERNAL;
    }
    memcpy(blob_copy, blob, blob_len);

    uintptr_t handle = 0;
    int rc = ITB_Triple_Open((char *)profile,
                             (void *)blob, blob_len,
                             (char *)itb_internal_opts_cstr(opts),
                             (void *)perm_master, perm_given ? perm_master_len : 0,
                             (void *)wrap_master, wrap_given ? wrap_master_len : 0,
                             masters_count, &handle);
    if (rc != (int)ITB_STATUS_OK) {
        free(blob_copy);
        free(pipe);
        return itb_internal_status(rc);
    }
    pipe->handle = handle;
    pipe->blob = blob_copy;
    pipe->blob_len = blob_len;
    *out = pipe;
    return ITB_STATUS_OK;
}

void itb_pipeline_free(itb_pipeline *pipe)
{
    if (pipe == NULL) {
        return;
    }
    if (pipe->handle != 0) {
        /* Free runs Close first Go-side (zeroing key material); the
         * status is deliberately ignored on the release path. */
        (void)ITB_Triple_Free(pipe->handle);
        pipe->handle = 0;
    }
    free(pipe->blob);
    pipe->blob = NULL;
    pipe->blob_len = 0;
    free(pipe);
}

const uint8_t *itb_pipeline_blob(const itb_pipeline *pipe)
{
    return pipe != NULL ? pipe->blob : NULL;
}

size_t itb_pipeline_blob_len(const itb_pipeline *pipe)
{
    return pipe != NULL ? pipe->blob_len : 0;
}

/* ------------------------------------------------------------------ */
/* Rekey                                                               */
/* ------------------------------------------------------------------ */

itb_status itb_pipeline_rekey(itb_pipeline *pipe,
                              const uint8_t *perm, size_t perm_len,
                              const uint8_t *wrap, size_t wrap_len)
{
    if (pipe == NULL) {
        return ITB_STATUS_BAD_INPUT;
    }
    size_t cap = pipe->blob_len > ITB_BLOB_CAP ? pipe->blob_len : ITB_BLOB_CAP;
    uint8_t *blob = malloc(cap);
    if (blob == NULL) {
        return ITB_STATUS_INTERNAL;
    }
    size_t blob_len = 0;
    int rc = ITB_Triple_Rekey(pipe->handle,
                              (void *)perm, perm_len,
                              (void *)wrap, wrap_len,
                              blob, cap, &blob_len);
    if (rc == (int)ITB_STATUS_BUFFER_TOO_SMALL && blob_len > cap) {
        uint8_t *grown = realloc(blob, blob_len);
        if (grown == NULL) {
            free(blob);
            return ITB_STATUS_INTERNAL;
        }
        blob = grown;
        cap = blob_len;
        rc = ITB_Triple_Rekey(pipe->handle,
                              (void *)perm, perm_len,
                              (void *)wrap, wrap_len,
                              blob, cap, &blob_len);
    }
    if (rc != (int)ITB_STATUS_OK) {
        free(blob);
        return itb_internal_status(rc);
    }
    free(pipe->blob);
    pipe->blob = blob;
    pipe->blob_len = blob_len;
    return ITB_STATUS_OK;
}

/* ------------------------------------------------------------------ */
/* Single Message encrypt / decrypt                                    */
/* ------------------------------------------------------------------ */

/* Shared body for the buffer-in / buffer-out cipher entries: single
 * retry-once dispatch over the caller-allocated-buffer convention.
 * On success *out (malloc'd, released via itb_bytes_free) and
 * *out_len are set; on failure they are NULL / 0. */
typedef int (*itb_cipher_fn)(uintptr_t handle, void *src, size_t src_len,
                             void *out, size_t out_cap, size_t *out_len);

static itb_status cipher_call(const itb_pipeline *pipe, itb_cipher_fn fn,
                              const uint8_t *src, size_t src_len,
                              uint8_t **out, size_t *out_len)
{
    if (out == NULL || out_len == NULL) {
        return ITB_STATUS_BAD_INPUT;
    }
    *out = NULL;
    *out_len = 0;
    if (pipe == NULL) {
        return ITB_STATUS_BAD_INPUT;
    }
    size_t cap = itb_internal_out_cap(src_len);
    uint8_t *buf = malloc(cap);
    if (buf == NULL) {
        return ITB_STATUS_INTERNAL;
    }
    size_t n = 0;
    int rc = fn(pipe->handle, (void *)src, src_len, buf, cap, &n);
    if (rc == (int)ITB_STATUS_BUFFER_TOO_SMALL && n > cap) {
        uint8_t *grown = realloc(buf, n);
        if (grown == NULL) {
            free(buf);
            return ITB_STATUS_INTERNAL;
        }
        buf = grown;
        cap = n;
        rc = fn(pipe->handle, (void *)src, src_len, buf, cap, &n);
    }
    if (rc != (int)ITB_STATUS_OK) {
        free(buf);
        return itb_internal_status(rc);
    }
    if (n < cap) {
        uint8_t *shrunk = realloc(buf, n > 0 ? n : 1);
        if (shrunk != NULL) {
            buf = shrunk;
        }
    }
    *out = buf;
    *out_len = n;
    return ITB_STATUS_OK;
}

itb_status itb_pipeline_encrypt_message(const itb_pipeline *pipe,
                                        const uint8_t *plain, size_t plain_len,
                                        uint8_t **wire_out, size_t *wire_len_out)
{
    return cipher_call(pipe, ITB_Triple_EncryptMessage,
                       plain, plain_len, wire_out, wire_len_out);
}

itb_status itb_pipeline_decrypt_message(const itb_pipeline *pipe,
                                        const uint8_t *wire, size_t wire_len,
                                        uint8_t **plain_out, size_t *plain_len_out)
{
    return cipher_call(pipe, ITB_Triple_DecryptMessage,
                       wire, wire_len, plain_out, plain_len_out);
}

/* ------------------------------------------------------------------ */
/* One-shot stream encrypt / decrypt                                   */
/* ------------------------------------------------------------------ */
/* Whole-buffer stream entries in a single FFI round trip: the
 * streaming wiring runs inside libitb, so the buffer-in / buffer-out
 * dispatch is identical to the Single Message pair. */

itb_status itb_pipeline_encrypt_stream_one_shot(const itb_pipeline *pipe,
                                                const uint8_t *plain, size_t plain_len,
                                                uint8_t **wire_out, size_t *wire_len_out)
{
    return cipher_call(pipe, ITB_Triple_EncryptStream,
                       plain, plain_len, wire_out, wire_len_out);
}

itb_status itb_pipeline_decrypt_stream_one_shot(const itb_pipeline *pipe,
                                                const uint8_t *wire, size_t wire_len,
                                                uint8_t **plain_out, size_t *plain_len_out)
{
    return cipher_call(pipe, ITB_Triple_DecryptStream,
                       wire, wire_len, plain_out, plain_len_out);
}

/* ------------------------------------------------------------------ */
/* Profile registration                                                */
/* ------------------------------------------------------------------ */

itb_status itb_register_profile(const char *name, const itb_opts *opts)
{
    if (name == NULL) {
        return ITB_STATUS_BAD_INPUT;
    }
    int rc = ITB_Triple_RegisterProfile((char *)name,
                                        (char *)itb_internal_opts_cstr(opts));
    return itb_internal_status(rc);
}
