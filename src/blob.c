/*
 * blob.c — native low-level Blob persistence (Blob128 / Blob256 /
 * Blob512).
 *
 * Mirrors Rust src/blob.rs / D src/itb/blob.d. Width-typed wrappers
 * pack the low-level encryptor material (per-seed hash key +
 * components + optional dedicated lockSeed + optional MAC key + name)
 * plus the captured process-wide configuration into one
 * self-describing JSON blob. The blob is mode-discriminated:
 * itb_blob*_export packs Single material, itb_blob*_export3 packs
 * Triple material; itb_blob*_import / itb_blob*_import3 are the
 * receivers.
 *
 * Macro pattern. The three width-typed surfaces (Blob128 / Blob256 /
 * Blob512) share the entire FFI dispatch under the hood — every
 * libitb entry point routes through one ITB_Blob_* function that
 * takes the handle and a width-agnostic argument set. The shared
 * helpers below take a raw uintptr_t handle; one ITB_DEFINE_BLOB(W)
 * macro generates the three sets of public entry points by delegating
 * to those helpers. Matches the Rust binding's macro_rules!
 * impl_blob_methods! pattern (one source-of-truth per method, three
 * type-safe expansions).
 *
 * Threading. Blob handles are not safe to share across threads
 * without external synchronisation — the per-handle setter / getter
 * calls mutate state on the libitb side. Distinct handles, each
 * owned by one thread, run independently. Same cross-binding
 * contract as the Easy Mode encryptor's per-instance discipline.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

/* ------------------------------------------------------------------ */
/* Shared low-level helpers — handle-based, width-agnostic              */
/* ------------------------------------------------------------------ */

static itb_status_t blob_check_handle(uintptr_t handle)
{
    if (handle == 0) {
        return itb_internal_set_error_msg(
            ITB_BAD_HANDLE, "blob handle is zero");
    }
    return ITB_OK;
}

static itb_status_t blob_int_getter(int (*fn)(uintptr_t, int *),
                                    uintptr_t handle, int *out_value)
{
    if (out_value == NULL) {
        return itb_internal_set_error_msg(ITB_BAD_INPUT, "out_value is NULL");
    }
    itb_status_t hc = blob_check_handle(handle);
    if (hc != ITB_OK) return hc;
    int st = ITB_OK;
    int v = fn(handle, &st);
    if (st != ITB_OK) {
        return itb_internal_set_error(st);
    }
    *out_value = v;
    itb_internal_reset_error();
    return ITB_OK;
}

static itb_status_t blob_set_key(uintptr_t handle, int slot,
                                 const uint8_t *key, size_t key_len)
{
    itb_status_t hc = blob_check_handle(handle);
    if (hc != ITB_OK) return hc;
    if (key_len > 0 && key == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "key_len > 0 but key is NULL");
    }
    void *ptr = (key_len == 0) ? NULL : (void *) key;
    int rc = ITB_Blob_SetKey(handle, slot, ptr, key_len);
    if (rc != ITB_OK) {
        return itb_internal_set_error(rc);
    }
    itb_internal_reset_error();
    return ITB_OK;
}

static itb_status_t blob_get_key(uintptr_t handle, int slot,
                                 uint8_t *out, size_t cap, size_t *out_len)
{
    if (out_len == NULL) {
        return itb_internal_set_error_msg(ITB_BAD_INPUT, "out_len is NULL");
    }
    *out_len = 0;
    itb_status_t hc = blob_check_handle(handle);
    if (hc != ITB_OK) return hc;

    /* Probe libitb for required size. */
    size_t need = 0;
    int rc = ITB_Blob_GetKey(handle, slot, NULL, 0, &need);
    if (rc == ITB_OK && need == 0) {
        itb_internal_reset_error();
        return ITB_OK;
    }
    if (rc != ITB_BUFFER_TOO_SMALL) {
        return itb_internal_set_error(rc);
    }
    if (out == NULL || cap < need) {
        *out_len = need;
        return itb_internal_set_error(ITB_BUFFER_TOO_SMALL);
    }

    size_t written = 0;
    rc = ITB_Blob_GetKey(handle, slot, out, cap, &written);
    if (rc != ITB_OK) {
        return itb_internal_set_error(rc);
    }
    *out_len = written;
    itb_internal_reset_error();
    return ITB_OK;
}

static itb_status_t blob_set_components(uintptr_t handle, int slot,
                                        const uint64_t *comps, size_t count)
{
    itb_status_t hc = blob_check_handle(handle);
    if (hc != ITB_OK) return hc;
    if (count > 0 && comps == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "count > 0 but comps is NULL");
    }
    /* libitb takes non-const for ABI legacy. */
    uint64_t *ptr = (count == 0) ? NULL : (uint64_t *) comps;
    int rc = ITB_Blob_SetComponents(handle, slot, ptr, count);
    if (rc != ITB_OK) {
        return itb_internal_set_error(rc);
    }
    itb_internal_reset_error();
    return ITB_OK;
}

static itb_status_t blob_get_components(uintptr_t handle, int slot,
                                        uint64_t *out, size_t cap_count,
                                        size_t *out_count)
{
    if (out_count == NULL) {
        return itb_internal_set_error_msg(ITB_BAD_INPUT, "out_count is NULL");
    }
    *out_count = 0;
    itb_status_t hc = blob_check_handle(handle);
    if (hc != ITB_OK) return hc;

    size_t need = 0;
    int rc = ITB_Blob_GetComponents(handle, slot, NULL, 0, &need);
    if (rc == ITB_OK && need == 0) {
        itb_internal_reset_error();
        return ITB_OK;
    }
    if (rc != ITB_BUFFER_TOO_SMALL) {
        return itb_internal_set_error(rc);
    }
    if (out == NULL || cap_count < need) {
        *out_count = need;
        return itb_internal_set_error(ITB_BUFFER_TOO_SMALL);
    }

    size_t written = 0;
    rc = ITB_Blob_GetComponents(handle, slot, out, cap_count, &written);
    if (rc != ITB_OK) {
        return itb_internal_set_error(rc);
    }
    *out_count = written;
    itb_internal_reset_error();
    return ITB_OK;
}

static itb_status_t blob_set_mac_key(uintptr_t handle,
                                     const uint8_t *key, size_t key_len)
{
    itb_status_t hc = blob_check_handle(handle);
    if (hc != ITB_OK) return hc;
    if (key_len > 0 && key == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "key_len > 0 but key is NULL");
    }
    void *ptr = (key_len == 0) ? NULL : (void *) key;
    int rc = ITB_Blob_SetMACKey(handle, ptr, key_len);
    if (rc != ITB_OK) {
        return itb_internal_set_error(rc);
    }
    itb_internal_reset_error();
    return ITB_OK;
}

static itb_status_t blob_get_mac_key(uintptr_t handle,
                                     uint8_t *out, size_t cap, size_t *out_len)
{
    if (out_len == NULL) {
        return itb_internal_set_error_msg(ITB_BAD_INPUT, "out_len is NULL");
    }
    *out_len = 0;
    itb_status_t hc = blob_check_handle(handle);
    if (hc != ITB_OK) return hc;

    size_t need = 0;
    int rc = ITB_Blob_GetMACKey(handle, NULL, 0, &need);
    if (rc == ITB_OK && need == 0) {
        itb_internal_reset_error();
        return ITB_OK;
    }
    if (rc != ITB_BUFFER_TOO_SMALL) {
        return itb_internal_set_error(rc);
    }
    if (out == NULL || cap < need) {
        *out_len = need;
        return itb_internal_set_error(ITB_BUFFER_TOO_SMALL);
    }

    size_t written = 0;
    rc = ITB_Blob_GetMACKey(handle, out, cap, &written);
    if (rc != ITB_OK) {
        return itb_internal_set_error(rc);
    }
    *out_len = written;
    itb_internal_reset_error();
    return ITB_OK;
}

static itb_status_t blob_set_mac_name(uintptr_t handle, const char *name)
{
    itb_status_t hc = blob_check_handle(handle);
    if (hc != ITB_OK) return hc;
    /* NULL or "" → clear (matches Rust's None / Some("") handling). */
    if (name == NULL || name[0] == '\0') {
        int rc = ITB_Blob_SetMACName(handle, NULL, 0);
        if (rc != ITB_OK) {
            return itb_internal_set_error(rc);
        }
        itb_internal_reset_error();
        return ITB_OK;
    }
    size_t n = strlen(name);
    if (n > (size_t) 0x7FFFFFFF) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "MAC name length exceeds INT32_MAX");
    }
    /* libitb takes char* (non-const) for ABI legacy. */
    int rc = ITB_Blob_SetMACName(handle, (char *) name, n);
    if (rc != ITB_OK) {
        return itb_internal_set_error(rc);
    }
    itb_internal_reset_error();
    return ITB_OK;
}

/* String-getter context shim for the MAC-name reader — routed through
 * itb_internal_read_string for uniform NUL-strip handling so *out_len
 * reports VISIBLE length (excluding NUL) on every code path. */
struct blob_mac_name_ctx { uintptr_t handle; };

static int call_blob_mac_name(char *out, size_t cap, size_t *out_len, void *ctx)
{
    struct blob_mac_name_ctx *c = (struct blob_mac_name_ctx *) ctx;
    return ITB_Blob_GetMACName(c->handle, out, cap, out_len);
}

static itb_status_t blob_get_mac_name(uintptr_t handle,
                                      char *out, size_t cap, size_t *out_len)
{
    itb_status_t hc = blob_check_handle(handle);
    if (hc != ITB_OK) return hc;
    struct blob_mac_name_ctx ctx = { handle };
    return itb_internal_read_string(call_blob_mac_name, &ctx,
                                    out, cap, out_len);
}

/* Probe-then-allocate for export / export3. The probe pass returns
 * STATUS_BUFFER_TOO_SMALL with the required size in *out_len; the
 * allocate-and-write pass copies into a freshly-malloc'd buffer that
 * the caller frees with itb_buffer_free(). */
typedef int (*blob_export_fn)(uintptr_t, int, void *, size_t, size_t *);

static itb_status_t blob_export_common(blob_export_fn fn,
                                       uintptr_t handle, int opts,
                                       uint8_t **out_buf, size_t *out_len)
{
    if (out_buf == NULL || out_len == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "out_buf or out_len is NULL");
    }
    *out_buf = NULL;
    *out_len = 0;
    itb_status_t hc = blob_check_handle(handle);
    if (hc != ITB_OK) return hc;

    size_t need = 0;
    int rc = fn(handle, opts, NULL, 0, &need);
    if (rc == ITB_OK && need == 0) {
        itb_internal_reset_error();
        return ITB_OK;
    }
    if (rc != ITB_BUFFER_TOO_SMALL) {
        return itb_internal_set_error(rc);
    }

    uint8_t *buf = (uint8_t *) malloc(need);
    if (buf == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }
    size_t written = 0;
    rc = fn(handle, opts, buf, need, &written);
    if (rc != ITB_OK) {
        free(buf);
        return itb_internal_set_error(rc);
    }
    *out_buf = buf;
    *out_len = written;
    itb_internal_reset_error();
    return ITB_OK;
}

typedef int (*blob_import_fn)(uintptr_t, void *, size_t);

static itb_status_t blob_import_common(blob_import_fn fn,
                                       uintptr_t handle,
                                       const void *blob, size_t blob_len)
{
    itb_status_t hc = blob_check_handle(handle);
    if (hc != ITB_OK) return hc;
    if (blob_len > 0 && blob == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "blob_len > 0 but blob is NULL");
    }
    void *ptr = (blob_len == 0) ? NULL : (void *) blob;
    int rc = fn(handle, ptr, blob_len);
    if (rc != ITB_OK) {
        return itb_internal_set_error(rc);
    }
    itb_internal_reset_error();
    return ITB_OK;
}

/* ------------------------------------------------------------------ */
/* Per-width entry points — generated via macro                         */
/* ------------------------------------------------------------------ */

/*
 * Generates the per-width concrete entry-point set. One expansion per
 * width yields 16 functions per blob type; the underlying logic lives
 * in the shared helpers above so the macro is purely a thin
 * type-safety adapter (struct itb_blobN -> uintptr_t handle).
 */
#define ITB_DEFINE_BLOB(W, FFI_NEW)                                              \
    itb_status_t itb_blob##W##_new(itb_blob##W##_t **out)                        \
    {                                                                            \
        if (out == NULL) {                                                       \
            return itb_internal_set_error_msg(ITB_BAD_INPUT, "out is NULL");     \
        }                                                                        \
        *out = NULL;                                                             \
        uintptr_t handle = 0;                                                    \
        int rc = FFI_NEW(&handle);                                               \
        if (rc != ITB_OK) {                                                      \
            return itb_internal_set_error(rc);                                   \
        }                                                                        \
        itb_blob##W##_t *b = (itb_blob##W##_t *) malloc(sizeof(*b));             \
        if (b == NULL) {                                                         \
            (void) ITB_Blob_Free(handle);                                        \
            return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");    \
        }                                                                        \
        b->handle = handle;                                                      \
        *out = b;                                                                \
        itb_internal_reset_error();                                              \
        return ITB_OK;                                                           \
    }                                                                            \
                                                                                 \
    void itb_blob##W##_free(itb_blob##W##_t *b)                                  \
    {                                                                            \
        if (b == NULL) return;                                                   \
        if (b->handle != 0) {                                                    \
            /* Best-effort release. Errors during free are swallowed —          \
             * there is no path to surface them and process-shutdown            \
             * ordering can be unpredictable. */                                 \
            (void) ITB_Blob_Free(b->handle);                                     \
            b->handle = 0;                                                       \
        }                                                                        \
        free(b);                                                                 \
    }                                                                            \
                                                                                 \
    itb_status_t itb_blob##W##_width(const itb_blob##W##_t *b, int *out_value)   \
    {                                                                            \
        if (b == NULL) {                                                         \
            return itb_internal_set_error_msg(ITB_BAD_INPUT, "blob is NULL");    \
        }                                                                        \
        return blob_int_getter(ITB_Blob_Width, b->handle, out_value);            \
    }                                                                            \
                                                                                 \
    itb_status_t itb_blob##W##_mode(const itb_blob##W##_t *b, int *out_value)    \
    {                                                                            \
        if (b == NULL) {                                                         \
            return itb_internal_set_error_msg(ITB_BAD_INPUT, "blob is NULL");    \
        }                                                                        \
        return blob_int_getter(ITB_Blob_Mode, b->handle, out_value);             \
    }                                                                            \
                                                                                 \
    itb_status_t itb_blob##W##_set_key(itb_blob##W##_t *b, int slot,             \
                                       const uint8_t *key, size_t key_len)      \
    {                                                                            \
        if (b == NULL) {                                                         \
            return itb_internal_set_error_msg(ITB_BAD_INPUT, "blob is NULL");    \
        }                                                                        \
        return blob_set_key(b->handle, slot, key, key_len);                      \
    }                                                                            \
                                                                                 \
    itb_status_t itb_blob##W##_get_key(const itb_blob##W##_t *b, int slot,       \
                                       uint8_t *out, size_t cap, size_t *out_len) \
    {                                                                            \
        if (b == NULL) {                                                         \
            return itb_internal_set_error_msg(ITB_BAD_INPUT, "blob is NULL");    \
        }                                                                        \
        return blob_get_key(b->handle, slot, out, cap, out_len);                 \
    }                                                                            \
                                                                                 \
    itb_status_t itb_blob##W##_set_components(itb_blob##W##_t *b, int slot,      \
                                              const uint64_t *comps,             \
                                              size_t count)                      \
    {                                                                            \
        if (b == NULL) {                                                         \
            return itb_internal_set_error_msg(ITB_BAD_INPUT, "blob is NULL");    \
        }                                                                        \
        return blob_set_components(b->handle, slot, comps, count);               \
    }                                                                            \
                                                                                 \
    itb_status_t itb_blob##W##_get_components(const itb_blob##W##_t *b, int slot, \
                                              uint64_t *out, size_t cap_count,   \
                                              size_t *out_count)                 \
    {                                                                            \
        if (b == NULL) {                                                         \
            return itb_internal_set_error_msg(ITB_BAD_INPUT, "blob is NULL");    \
        }                                                                        \
        return blob_get_components(b->handle, slot, out, cap_count, out_count);  \
    }                                                                            \
                                                                                 \
    itb_status_t itb_blob##W##_set_mac_key(itb_blob##W##_t *b,                   \
                                           const uint8_t *key, size_t key_len)   \
    {                                                                            \
        if (b == NULL) {                                                         \
            return itb_internal_set_error_msg(ITB_BAD_INPUT, "blob is NULL");    \
        }                                                                        \
        return blob_set_mac_key(b->handle, key, key_len);                        \
    }                                                                            \
                                                                                 \
    itb_status_t itb_blob##W##_get_mac_key(const itb_blob##W##_t *b,             \
                                           uint8_t *out, size_t cap,             \
                                           size_t *out_len)                      \
    {                                                                            \
        if (b == NULL) {                                                         \
            return itb_internal_set_error_msg(ITB_BAD_INPUT, "blob is NULL");    \
        }                                                                        \
        return blob_get_mac_key(b->handle, out, cap, out_len);                   \
    }                                                                            \
                                                                                 \
    itb_status_t itb_blob##W##_set_mac_name(itb_blob##W##_t *b, const char *name) \
    {                                                                            \
        if (b == NULL) {                                                         \
            return itb_internal_set_error_msg(ITB_BAD_INPUT, "blob is NULL");    \
        }                                                                        \
        return blob_set_mac_name(b->handle, name);                               \
    }                                                                            \
                                                                                 \
    itb_status_t itb_blob##W##_get_mac_name(const itb_blob##W##_t *b,            \
                                            char *out, size_t cap,               \
                                            size_t *out_len)                     \
    {                                                                            \
        if (b == NULL) {                                                         \
            return itb_internal_set_error_msg(ITB_BAD_INPUT, "blob is NULL");    \
        }                                                                        \
        return blob_get_mac_name(b->handle, out, cap, out_len);                  \
    }                                                                            \
                                                                                 \
    itb_status_t itb_blob##W##_export(const itb_blob##W##_t *b, int opts,        \
                                      uint8_t **out_buf, size_t *out_len)        \
    {                                                                            \
        if (b == NULL) {                                                         \
            if (out_buf != NULL) *out_buf = NULL;                                \
            if (out_len != NULL) *out_len = 0;                                   \
            return itb_internal_set_error_msg(ITB_BAD_INPUT, "blob is NULL");    \
        }                                                                        \
        return blob_export_common(ITB_Blob_Export, b->handle, opts,              \
                                  out_buf, out_len);                             \
    }                                                                            \
                                                                                 \
    itb_status_t itb_blob##W##_export3(const itb_blob##W##_t *b, int opts,       \
                                       uint8_t **out_buf, size_t *out_len)       \
    {                                                                            \
        if (b == NULL) {                                                         \
            if (out_buf != NULL) *out_buf = NULL;                                \
            if (out_len != NULL) *out_len = 0;                                   \
            return itb_internal_set_error_msg(ITB_BAD_INPUT, "blob is NULL");    \
        }                                                                        \
        return blob_export_common(ITB_Blob_Export3, b->handle, opts,             \
                                  out_buf, out_len);                             \
    }                                                                            \
                                                                                 \
    itb_status_t itb_blob##W##_import(itb_blob##W##_t *b,                        \
                                      const void *blob_, size_t blob_len)        \
    {                                                                            \
        if (b == NULL) {                                                         \
            return itb_internal_set_error_msg(ITB_BAD_INPUT, "blob is NULL");    \
        }                                                                        \
        return blob_import_common(ITB_Blob_Import, b->handle, blob_, blob_len);  \
    }                                                                            \
                                                                                 \
    itb_status_t itb_blob##W##_import3(itb_blob##W##_t *b,                       \
                                       const void *blob_, size_t blob_len)       \
    {                                                                            \
        if (b == NULL) {                                                         \
            return itb_internal_set_error_msg(ITB_BAD_INPUT, "blob is NULL");    \
        }                                                                        \
        return blob_import_common(ITB_Blob_Import3, b->handle, blob_, blob_len); \
    }

ITB_DEFINE_BLOB(128, ITB_Blob128_New)
ITB_DEFINE_BLOB(256, ITB_Blob256_New)
ITB_DEFINE_BLOB(512, ITB_Blob512_New)

#undef ITB_DEFINE_BLOB
