/*
 * itb_pipeline.c — Triple Pipeline handle lifecycle, persistence
 * (save / load), the Single Message cipher entries, and the profile
 * record entries (inspect / register / lookup / profiles).
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
/* Caller-allocated-buffer helper                                      */
/* ------------------------------------------------------------------ */

/* Single retry-once dispatch site for every variable-size output
 * buffer (Init / Rekey / Save / Inspect / Lookup / Profiles):
 * pre-allocate cap, and on ITB_STATUS_BUFFER_TOO_SMALL retry once
 * with the exact size libitb reported. On success *out (malloc'd,
 * `extra` spare bytes past *out_len, zeroed) and *out_len are set;
 * on failure they are NULL / 0 and the status is returned. */
typedef int (*itb_buf_fn)(void *ctx, void *out, size_t out_cap, size_t *out_len);

static itb_status buf_call(itb_buf_fn fn, void *ctx, size_t cap, size_t extra,
                           uint8_t **out, size_t *out_len)
{
    *out = NULL;
    *out_len = 0;
    uint8_t *buf = malloc(cap + extra);
    if (buf == NULL) {
        return ITB_STATUS_INTERNAL;
    }
    size_t n = 0;
    int rc = fn(ctx, buf, cap, &n);
    if (rc == (int)ITB_STATUS_BUFFER_TOO_SMALL && n > cap) {
        uint8_t *grown = realloc(buf, n + extra);
        if (grown == NULL) {
            free(buf);
            return ITB_STATUS_INTERNAL;
        }
        buf = grown;
        cap = n;
        rc = fn(ctx, buf, cap, &n);
    }
    if (rc != (int)ITB_STATUS_OK) {
        free(buf);
        return itb_internal_status(rc);
    }
    if (n + extra < cap + extra) {
        uint8_t *shrunk = realloc(buf, n + extra > 0 ? n + extra : 1);
        if (shrunk != NULL) {
            buf = shrunk;
        }
    }
    memset(buf + n, 0, extra);
    *out = buf;
    *out_len = n;
    return ITB_STATUS_OK;
}

/* Wraps a NUL-terminated JSON string out of a buf_call result. */
static itb_status json_call(itb_buf_fn fn, void *ctx, char **json_out)
{
    if (json_out == NULL) {
        return ITB_STATUS_BAD_INPUT;
    }
    uint8_t *buf = NULL;
    size_t n = 0;
    itb_status st = buf_call(fn, ctx, ITB_BLOB_CAP, 1, &buf, &n);
    *json_out = (char *)buf;
    return st;
}

/* ------------------------------------------------------------------ */
/* Init / Load / Free                                                  */
/* ------------------------------------------------------------------ */

struct init_ctx {
    const char *profile;
    const char *opts;
    uintptr_t handle;
};

static int init_fn(void *ctx, void *out, size_t cap, size_t *out_len)
{
    struct init_ctx *c = ctx;
    /* Go closes the undersized attempt; the retry re-runs Init and
     * yields a fresh session. */
    c->handle = 0;
    return ITB_Triple_Init((char *)c->profile, (char *)c->opts,
                           out, cap, out_len, &c->handle);
}

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
    struct init_ctx ctx = { profile, itb_internal_opts_cstr(opts), 0 };
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    itb_status st = buf_call(init_fn, &ctx, ITB_BLOB_CAP, 0, &blob, &blob_len);
    /* The Init blob is not retained binding-side; itb_pipeline_save
     * reads the current bytes from libitb. */
    free(blob);
    if (st != ITB_STATUS_OK) {
        free(pipe);
        return st;
    }
    pipe->handle = ctx.handle;
    *out = pipe;
    return ITB_STATUS_OK;
}

/* Shared tail of the two load entries: wraps a libitb handle. */
static itb_status wrap_handle(int rc, uintptr_t handle, itb_pipeline **out)
{
    if (rc != (int)ITB_STATUS_OK) {
        return itb_internal_status(rc);
    }
    itb_pipeline *pipe = calloc(1, sizeof(*pipe));
    if (pipe == NULL) {
        (void)ITB_Triple_Free(handle);
        return ITB_STATUS_INTERNAL;
    }
    pipe->handle = handle;
    *out = pipe;
    return ITB_STATUS_OK;
}

/* The masters pair crosses as (perm, wrap, count): both absent → 0,
 * otherwise 2 — libitb validates the pair. */
static size_t masters_count(const uint8_t *perm, size_t perm_len,
                            const uint8_t *wrap, size_t wrap_len)
{
    int perm_given = perm != NULL && perm_len > 0;
    int wrap_given = wrap != NULL && wrap_len > 0;
    return (perm_given || wrap_given) ? 2 : 0;
}

itb_status itb_pipeline_load(const uint8_t *blob, size_t blob_len,
                             const uint8_t *perm_master, size_t perm_master_len,
                             const uint8_t *wrap_master, size_t wrap_master_len,
                             itb_pipeline **out)
{
    if (out == NULL) {
        return ITB_STATUS_BAD_INPUT;
    }
    *out = NULL;
    if (blob == NULL) {
        return ITB_STATUS_BAD_INPUT;
    }
    uintptr_t handle = 0;
    int rc = ITB_Triple_Load((void *)blob, blob_len,
                             (void *)perm_master, perm_master_len,
                             (void *)wrap_master, wrap_master_len,
                             masters_count(perm_master, perm_master_len,
                                           wrap_master, wrap_master_len),
                             &handle);
    return wrap_handle(rc, handle, out);
}

itb_status itb_pipeline_load_f(const char *path,
                               const uint8_t *perm_master, size_t perm_master_len,
                               const uint8_t *wrap_master, size_t wrap_master_len,
                               itb_pipeline **out)
{
    if (out == NULL) {
        return ITB_STATUS_BAD_INPUT;
    }
    *out = NULL;
    if (path == NULL) {
        return ITB_STATUS_BAD_INPUT;
    }
    uintptr_t handle = 0;
    int rc = ITB_Triple_LoadF((char *)path,
                              (void *)perm_master, perm_master_len,
                              (void *)wrap_master, wrap_master_len,
                              masters_count(perm_master, perm_master_len,
                                            wrap_master, wrap_master_len),
                              &handle);
    return wrap_handle(rc, handle, out);
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
    free(pipe);
}

/* ------------------------------------------------------------------ */
/* Save / MaxWorkers / Rekey                                           */
/* ------------------------------------------------------------------ */

static int save_fn(void *ctx, void *out, size_t cap, size_t *out_len)
{
    const itb_pipeline *pipe = ctx;
    return ITB_Triple_Save(pipe->handle, out, cap, out_len);
}

itb_status itb_pipeline_save(const itb_pipeline *pipe,
                             uint8_t **blob_out, size_t *blob_len_out)
{
    if (blob_out == NULL || blob_len_out == NULL) {
        return ITB_STATUS_BAD_INPUT;
    }
    *blob_out = NULL;
    *blob_len_out = 0;
    if (pipe == NULL) {
        return ITB_STATUS_BAD_INPUT;
    }
    return buf_call(save_fn, (void *)pipe, ITB_BLOB_CAP, 0, blob_out, blob_len_out);
}

itb_status itb_pipeline_save_f(const itb_pipeline *pipe, const char *path)
{
    if (pipe == NULL || path == NULL) {
        return ITB_STATUS_BAD_INPUT;
    }
    return itb_internal_status(ITB_Triple_SaveF(pipe->handle, (char *)path));
}

itb_status itb_pipeline_max_workers(const itb_pipeline *pipe, int n)
{
    if (pipe == NULL) {
        return ITB_STATUS_BAD_INPUT;
    }
    return itb_internal_status(ITB_Triple_MaxWorkers(pipe->handle, n));
}

struct rekey_ctx {
    const itb_pipeline *pipe;
    const uint8_t *perm;
    size_t perm_len;
    const uint8_t *wrap;
    size_t wrap_len;
};

static int rekey_fn(void *ctx, void *out, size_t cap, size_t *out_len)
{
    struct rekey_ctx *c = ctx;
    return ITB_Triple_Rekey(c->pipe->handle,
                            (void *)c->perm, c->perm_len,
                            (void *)c->wrap, c->wrap_len,
                            out, cap, out_len);
}

itb_status itb_pipeline_rekey(itb_pipeline *pipe,
                              const uint8_t *perm, size_t perm_len,
                              const uint8_t *wrap, size_t wrap_len,
                              uint8_t **blob_out, size_t *blob_len_out)
{
    if (blob_out != NULL) {
        *blob_out = NULL;
    }
    if (blob_len_out != NULL) {
        *blob_len_out = 0;
    }
    if (pipe == NULL) {
        return ITB_STATUS_BAD_INPUT;
    }
    struct rekey_ctx ctx = { pipe, perm, perm_len, wrap, wrap_len };
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    itb_status st = buf_call(rekey_fn, &ctx, ITB_BLOB_CAP, 0, &blob, &blob_len);
    if (st != ITB_STATUS_OK) {
        return st;
    }
    if (blob_out != NULL && blob_len_out != NULL) {
        *blob_out = blob;
        *blob_len_out = blob_len;
    } else {
        free(blob);
    }
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
/* Profile records: inspect / register / lookup / profiles             */
/* ------------------------------------------------------------------ */

struct inspect_ctx {
    const uint8_t *blob;
    size_t blob_len;
};

static int inspect_fn(void *ctx, void *out, size_t cap, size_t *out_len)
{
    struct inspect_ctx *c = ctx;
    return ITB_Triple_Inspect((void *)c->blob, c->blob_len, out, cap, out_len);
}

itb_status itb_inspect(const uint8_t *blob, size_t blob_len, char **json_out)
{
    if (json_out == NULL) {
        return ITB_STATUS_BAD_INPUT;
    }
    *json_out = NULL;
    if (blob == NULL) {
        return ITB_STATUS_BAD_INPUT;
    }
    struct inspect_ctx ctx = { blob, blob_len };
    return json_call(inspect_fn, &ctx, json_out);
}

itb_status itb_register(const char *name, const char *profile_json)
{
    if (name == NULL || profile_json == NULL) {
        return ITB_STATUS_BAD_INPUT;
    }
    return itb_internal_status(ITB_Triple_Register((char *)name, (char *)profile_json));
}

static int lookup_fn(void *ctx, void *out, size_t cap, size_t *out_len)
{
    return ITB_Triple_Lookup((char *)ctx, out, cap, out_len);
}

itb_status itb_lookup(const char *name, char **json_out)
{
    if (json_out == NULL) {
        return ITB_STATUS_BAD_INPUT;
    }
    *json_out = NULL;
    if (name == NULL) {
        return ITB_STATUS_BAD_INPUT;
    }
    return json_call(lookup_fn, (void *)name, json_out);
}

static int profiles_fn(void *ctx, void *out, size_t cap, size_t *out_len)
{
    (void)ctx;
    return ITB_Triple_Profiles(out, cap, out_len);
}

itb_status itb_profiles(char **json_out)
{
    if (json_out == NULL) {
        return ITB_STATUS_BAD_INPUT;
    }
    *json_out = NULL;
    return json_call(profiles_fn, NULL, json_out);
}
