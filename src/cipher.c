/*
 * cipher.c — low-level encrypt / decrypt entry points.
 *
 * Mirrors Rust src/encrypt.rs / D src/itb/cipher.d. Each entry point
 * follows the libitb probe-then-allocate idiom: the first FFI call
 * passes cap=0 to discover the required output size via
 * STATUS_BUFFER_TOO_SMALL, then a second call writes the produced
 * bytes into a freshly-allocated buffer.
 *
 * Output ownership: the wrapper malloc()-s the buffer; the caller frees
 * it via itb_buffer_free(). Empty plaintext / ciphertext is rejected
 * by libitb itself with ITB_ENCRYPT_FAILED (Go-side `Encrypt128` /
 * `Decrypt128` family returns "itb: empty data"); the binding
 * propagates the rejection verbatim. The OK + need=0 short-circuit
 * paths in the dispatch helpers below are defensive — they guard
 * against a future libitb that might start accepting empty input
 * silently — but they are dead code under the current contract.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "internal.h"

void itb_buffer_free(uint8_t *buf)
{
    /* Wrapper around free() — single audit-time deallocation site +
     * cross-binding-friendly entry point if applications interpose
     * malloc/free at their boundary. */
    free(buf);
}

/* ------------------------------------------------------------------ */
/* Internal dispatch helpers                                           */
/* ------------------------------------------------------------------ */

/* Single-Ouroboros (3 seeds) entry-point signature. */
typedef int (*fn_single_t)(uintptr_t, uintptr_t, uintptr_t,
                           void *, size_t, void *, size_t, size_t *);

/* Triple-Ouroboros (7 seeds) entry-point signature. */
typedef int (*fn_triple_t)(uintptr_t, uintptr_t, uintptr_t, uintptr_t,
                           uintptr_t, uintptr_t, uintptr_t,
                           void *, size_t, void *, size_t, size_t *);

/* Single-auth (3 seeds + MAC) signature. */
typedef int (*fn_auth_t)(uintptr_t, uintptr_t, uintptr_t, uintptr_t,
                         void *, size_t, void *, size_t, size_t *);

/* Triple-auth (7 seeds + MAC) signature. */
typedef int (*fn_auth3_t)(uintptr_t, uintptr_t, uintptr_t, uintptr_t,
                          uintptr_t, uintptr_t, uintptr_t, uintptr_t,
                          void *, size_t, void *, size_t, size_t *);

static itb_status_t common_single(fn_single_t fn,
                                  uintptr_t h_n, uintptr_t h_d, uintptr_t h_s,
                                  const void *payload, size_t payload_len,
                                  uint8_t **out_buf, size_t *out_len)
{
    *out_buf = NULL;
    *out_len = 0;

    void *in_ptr = (payload_len == 0) ? NULL : (void *) payload;

    /* Pre-allocate from the saturating 1.25x + 128 KiB upper bound and
     * call once. The C ABI runs the full crypto on every call regardless
     * of out-buffer capacity (probing with cap=0 to discover the
     * required size would re-run the work on the retry); skipping the
     * probe halves the per-chunk cost on the steady-state path. The
     * retry-once branch on STATUS_BUFFER_TOO_SMALL is the safety net
     * for combinations outside the measured expansion-ratio matrix. */
    size_t cap = itb_internal_buf_cap(payload_len);
    uint8_t *buf = (uint8_t *) malloc(cap);
    if (buf == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }

    size_t written = 0;
    int rc = fn(h_n, h_d, h_s, in_ptr, payload_len, buf, cap, &written);
    if (rc == ITB_BUFFER_TOO_SMALL) {
        size_t need = written;
        if (need == 0) {
            free(buf);
            return itb_internal_set_error_msg(
                ITB_INTERNAL, "BUFFER_TOO_SMALL with zero need");
        }
        uint8_t *resized = (uint8_t *) realloc(buf, need);
        if (resized == NULL) {
            free(buf);
            return itb_internal_set_error_msg(ITB_INTERNAL, "realloc failed");
        }
        buf = resized;
        cap = need;
        rc = fn(h_n, h_d, h_s, in_ptr, payload_len, buf, cap, &written);
    }
    if (rc != ITB_OK) {
        free(buf);
        return itb_internal_set_error(rc);
    }
    if (written == 0) {
        /* Empty output (defensive — current libitb rejects empty input
         * with ITB_ENCRYPT_FAILED, so this branch is dead under the
         * shipped contract). */
        free(buf);
        itb_internal_reset_error();
        return ITB_OK;
    }
    *out_buf = buf;
    *out_len = written;
    itb_internal_reset_error();
    return ITB_OK;
}

static itb_status_t common_triple(fn_triple_t fn,
                                  uintptr_t h_n,
                                  uintptr_t h_d1, uintptr_t h_d2, uintptr_t h_d3,
                                  uintptr_t h_s1, uintptr_t h_s2, uintptr_t h_s3,
                                  const void *payload, size_t payload_len,
                                  uint8_t **out_buf, size_t *out_len)
{
    *out_buf = NULL;
    *out_len = 0;

    void *in_ptr = (payload_len == 0) ? NULL : (void *) payload;

    size_t cap = itb_internal_buf_cap(payload_len);
    uint8_t *buf = (uint8_t *) malloc(cap);
    if (buf == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }

    size_t written = 0;
    int rc = fn(h_n, h_d1, h_d2, h_d3, h_s1, h_s2, h_s3,
                in_ptr, payload_len, buf, cap, &written);
    if (rc == ITB_BUFFER_TOO_SMALL) {
        size_t need = written;
        if (need == 0) {
            free(buf);
            return itb_internal_set_error_msg(
                ITB_INTERNAL, "BUFFER_TOO_SMALL with zero need");
        }
        uint8_t *resized = (uint8_t *) realloc(buf, need);
        if (resized == NULL) {
            free(buf);
            return itb_internal_set_error_msg(ITB_INTERNAL, "realloc failed");
        }
        buf = resized;
        cap = need;
        rc = fn(h_n, h_d1, h_d2, h_d3, h_s1, h_s2, h_s3,
                in_ptr, payload_len, buf, cap, &written);
    }
    if (rc != ITB_OK) {
        free(buf);
        return itb_internal_set_error(rc);
    }
    if (written == 0) {
        free(buf);
        itb_internal_reset_error();
        return ITB_OK;
    }
    *out_buf = buf;
    *out_len = written;
    itb_internal_reset_error();
    return ITB_OK;
}

static itb_status_t common_auth(fn_auth_t fn,
                                uintptr_t h_n, uintptr_t h_d, uintptr_t h_s,
                                uintptr_t h_m,
                                const void *payload, size_t payload_len,
                                uint8_t **out_buf, size_t *out_len)
{
    *out_buf = NULL;
    *out_len = 0;

    void *in_ptr = (payload_len == 0) ? NULL : (void *) payload;

    size_t cap = itb_internal_buf_cap(payload_len);
    uint8_t *buf = (uint8_t *) malloc(cap);
    if (buf == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }

    size_t written = 0;
    int rc = fn(h_n, h_d, h_s, h_m, in_ptr, payload_len, buf, cap, &written);
    if (rc == ITB_BUFFER_TOO_SMALL) {
        size_t need = written;
        if (need == 0) {
            free(buf);
            return itb_internal_set_error_msg(
                ITB_INTERNAL, "BUFFER_TOO_SMALL with zero need");
        }
        uint8_t *resized = (uint8_t *) realloc(buf, need);
        if (resized == NULL) {
            free(buf);
            return itb_internal_set_error_msg(ITB_INTERNAL, "realloc failed");
        }
        buf = resized;
        cap = need;
        rc = fn(h_n, h_d, h_s, h_m, in_ptr, payload_len, buf, cap, &written);
    }
    if (rc != ITB_OK) {
        free(buf);
        return itb_internal_set_error(rc);
    }
    if (written == 0) {
        free(buf);
        itb_internal_reset_error();
        return ITB_OK;
    }
    *out_buf = buf;
    *out_len = written;
    itb_internal_reset_error();
    return ITB_OK;
}

static itb_status_t common_auth3(fn_auth3_t fn,
                                 uintptr_t h_n,
                                 uintptr_t h_d1, uintptr_t h_d2, uintptr_t h_d3,
                                 uintptr_t h_s1, uintptr_t h_s2, uintptr_t h_s3,
                                 uintptr_t h_m,
                                 const void *payload, size_t payload_len,
                                 uint8_t **out_buf, size_t *out_len)
{
    *out_buf = NULL;
    *out_len = 0;

    void *in_ptr = (payload_len == 0) ? NULL : (void *) payload;

    size_t cap = itb_internal_buf_cap(payload_len);
    uint8_t *buf = (uint8_t *) malloc(cap);
    if (buf == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }

    size_t written = 0;
    int rc = fn(h_n, h_d1, h_d2, h_d3, h_s1, h_s2, h_s3, h_m,
                in_ptr, payload_len, buf, cap, &written);
    if (rc == ITB_BUFFER_TOO_SMALL) {
        size_t need = written;
        if (need == 0) {
            free(buf);
            return itb_internal_set_error_msg(
                ITB_INTERNAL, "BUFFER_TOO_SMALL with zero need");
        }
        uint8_t *resized = (uint8_t *) realloc(buf, need);
        if (resized == NULL) {
            free(buf);
            return itb_internal_set_error_msg(ITB_INTERNAL, "realloc failed");
        }
        buf = resized;
        cap = need;
        rc = fn(h_n, h_d1, h_d2, h_d3, h_s1, h_s2, h_s3, h_m,
                in_ptr, payload_len, buf, cap, &written);
    }
    if (rc != ITB_OK) {
        free(buf);
        return itb_internal_set_error(rc);
    }
    if (written == 0) {
        free(buf);
        itb_internal_reset_error();
        return ITB_OK;
    }
    *out_buf = buf;
    *out_len = written;
    itb_internal_reset_error();
    return ITB_OK;
}

/* ------------------------------------------------------------------ */
/* Argument-validation helpers                                         */
/* ------------------------------------------------------------------ */

#define CHECK_3(n, d, s, out_buf, out_len)                                     \
    do {                                                                       \
        if (out_buf == NULL || out_len == NULL) {                              \
            return itb_internal_set_error_msg(                                 \
                ITB_BAD_INPUT, "out_buf or out_len is NULL");                  \
        }                                                                      \
        if (out_buf != NULL) *out_buf = NULL;                                  \
        if (out_len != NULL) *out_len = 0;                                     \
        if (n == NULL || d == NULL || s == NULL) {                             \
            return itb_internal_set_error_msg(                                 \
                ITB_BAD_INPUT, "noise/data/start seed is NULL");               \
        }                                                                      \
    } while (0)

#define CHECK_7(n, d1, d2, d3, s1, s2, s3, out_buf, out_len)                   \
    do {                                                                       \
        if (out_buf == NULL || out_len == NULL) {                              \
            return itb_internal_set_error_msg(                                 \
                ITB_BAD_INPUT, "out_buf or out_len is NULL");                  \
        }                                                                      \
        if (out_buf != NULL) *out_buf = NULL;                                  \
        if (out_len != NULL) *out_len = 0;                                     \
        if (n == NULL || d1 == NULL || d2 == NULL || d3 == NULL ||             \
            s1 == NULL || s2 == NULL || s3 == NULL) {                          \
            return itb_internal_set_error_msg(                                 \
                ITB_BAD_INPUT, "one of the seven seeds is NULL");              \
        }                                                                      \
    } while (0)

/* ------------------------------------------------------------------ */
/* Public entry points                                                 */
/* ------------------------------------------------------------------ */

itb_status_t itb_encrypt(const itb_seed_t *noise,
                         const itb_seed_t *data,
                         const itb_seed_t *start,
                         const void *plaintext, size_t plaintext_len,
                         uint8_t **out_buf, size_t *out_len)
{
    CHECK_3(noise, data, start, out_buf, out_len);
    return common_single(ITB_Encrypt,
                         noise->handle, data->handle, start->handle,
                         plaintext, plaintext_len, out_buf, out_len);
}

itb_status_t itb_decrypt(const itb_seed_t *noise,
                         const itb_seed_t *data,
                         const itb_seed_t *start,
                         const void *ciphertext, size_t ciphertext_len,
                         uint8_t **out_buf, size_t *out_len)
{
    CHECK_3(noise, data, start, out_buf, out_len);
    return common_single(ITB_Decrypt,
                         noise->handle, data->handle, start->handle,
                         ciphertext, ciphertext_len, out_buf, out_len);
}

itb_status_t itb_encrypt_auth(const itb_seed_t *noise,
                              const itb_seed_t *data,
                              const itb_seed_t *start,
                              const itb_mac_t *mac,
                              const void *plaintext, size_t plaintext_len,
                              uint8_t **out_buf, size_t *out_len)
{
    CHECK_3(noise, data, start, out_buf, out_len);
    if (mac == NULL) {
        return itb_internal_set_error_msg(ITB_BAD_INPUT, "mac is NULL");
    }
    return common_auth(ITB_EncryptAuth,
                       noise->handle, data->handle, start->handle,
                       mac->handle,
                       plaintext, plaintext_len, out_buf, out_len);
}

itb_status_t itb_decrypt_auth(const itb_seed_t *noise,
                              const itb_seed_t *data,
                              const itb_seed_t *start,
                              const itb_mac_t *mac,
                              const void *ciphertext, size_t ciphertext_len,
                              uint8_t **out_buf, size_t *out_len)
{
    CHECK_3(noise, data, start, out_buf, out_len);
    if (mac == NULL) {
        return itb_internal_set_error_msg(ITB_BAD_INPUT, "mac is NULL");
    }
    return common_auth(ITB_DecryptAuth,
                       noise->handle, data->handle, start->handle,
                       mac->handle,
                       ciphertext, ciphertext_len, out_buf, out_len);
}

itb_status_t itb_encrypt_triple(const itb_seed_t *noise,
                                const itb_seed_t *data1,
                                const itb_seed_t *data2,
                                const itb_seed_t *data3,
                                const itb_seed_t *start1,
                                const itb_seed_t *start2,
                                const itb_seed_t *start3,
                                const void *plaintext, size_t plaintext_len,
                                uint8_t **out_buf, size_t *out_len)
{
    CHECK_7(noise, data1, data2, data3, start1, start2, start3,
            out_buf, out_len);
    return common_triple(ITB_Encrypt3,
                         noise->handle,
                         data1->handle, data2->handle, data3->handle,
                         start1->handle, start2->handle, start3->handle,
                         plaintext, plaintext_len, out_buf, out_len);
}

itb_status_t itb_decrypt_triple(const itb_seed_t *noise,
                                const itb_seed_t *data1,
                                const itb_seed_t *data2,
                                const itb_seed_t *data3,
                                const itb_seed_t *start1,
                                const itb_seed_t *start2,
                                const itb_seed_t *start3,
                                const void *ciphertext, size_t ciphertext_len,
                                uint8_t **out_buf, size_t *out_len)
{
    CHECK_7(noise, data1, data2, data3, start1, start2, start3,
            out_buf, out_len);
    return common_triple(ITB_Decrypt3,
                         noise->handle,
                         data1->handle, data2->handle, data3->handle,
                         start1->handle, start2->handle, start3->handle,
                         ciphertext, ciphertext_len, out_buf, out_len);
}

itb_status_t itb_encrypt_auth_triple(const itb_seed_t *noise,
                                     const itb_seed_t *data1,
                                     const itb_seed_t *data2,
                                     const itb_seed_t *data3,
                                     const itb_seed_t *start1,
                                     const itb_seed_t *start2,
                                     const itb_seed_t *start3,
                                     const itb_mac_t *mac,
                                     const void *plaintext, size_t plaintext_len,
                                     uint8_t **out_buf, size_t *out_len)
{
    CHECK_7(noise, data1, data2, data3, start1, start2, start3,
            out_buf, out_len);
    if (mac == NULL) {
        return itb_internal_set_error_msg(ITB_BAD_INPUT, "mac is NULL");
    }
    return common_auth3(ITB_EncryptAuth3,
                        noise->handle,
                        data1->handle, data2->handle, data3->handle,
                        start1->handle, start2->handle, start3->handle,
                        mac->handle,
                        plaintext, plaintext_len, out_buf, out_len);
}

itb_status_t itb_decrypt_auth_triple(const itb_seed_t *noise,
                                     const itb_seed_t *data1,
                                     const itb_seed_t *data2,
                                     const itb_seed_t *data3,
                                     const itb_seed_t *start1,
                                     const itb_seed_t *start2,
                                     const itb_seed_t *start3,
                                     const itb_mac_t *mac,
                                     const void *ciphertext, size_t ciphertext_len,
                                     uint8_t **out_buf, size_t *out_len)
{
    CHECK_7(noise, data1, data2, data3, start1, start2, start3,
            out_buf, out_len);
    if (mac == NULL) {
        return itb_internal_set_error_msg(ITB_BAD_INPUT, "mac is NULL");
    }
    return common_auth3(ITB_DecryptAuth3,
                        noise->handle,
                        data1->handle, data2->handle, data3->handle,
                        start1->handle, start2->handle, start3->handle,
                        mac->handle,
                        ciphertext, ciphertext_len, out_buf, out_len);
}
