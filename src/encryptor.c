/*
 * encryptor.c — Easy Mode encryptor wrapper.
 *
 * Mirrors Rust src/encryptor.rs / D src/itb/encryptor.d. The
 * `itb_encryptor_t` opaque struct wraps the libitb `easy/` package: one
 * constructor call replaces the lower-level seven-line setup ceremony
 * (hash factory, three or seven seeds, MAC closure, container-config
 * wiring) and returns a handle that owns its own per-instance Config
 * snapshot. Two encryptors with different settings can be used in
 * parallel without cross-contamination of the process-wide ITB state.
 *
 * Output-buffer cache. The cipher methods reuse a per-encryptor
 * malloc'd buffer as the libitb FFI write target so the size-probe
 * round-trip is skipped on the steady-state hot path; the buffer grows
 * on demand and survives between calls. Each cipher call hands the
 * caller a freshly malloc'd user-owned copy of the result (memcpy from
 * the cache); the caller frees it with itb_buffer_free. Returning a
 * user-owned copy (rather than a pointer into the cache) avoids a
 * subtle aliasing footgun where the previous-call output buffer
 * passed back as input on the same encryptor would be overwritten by
 * the FFI write target mid-call. The cached bytes (the most recent
 * ciphertext or plaintext) are zeroed on grow / close / free.
 *
 * Thread-safety. Cipher methods write into the per-instance output
 * cache and are NOT safe to invoke concurrently against the same
 * encryptor — the cache pointer / capacity race with another thread's
 * cipher call. Per-instance setters race likewise. Sharing one
 * itb_encryptor_t value across threads requires external
 * synchronisation. Distinct encryptor values, each owned by one
 * thread, run independently against the libitb worker pool.
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

/*
 * Easy-aware error capture. On ITB_EASY_MISMATCH the caller can read
 * the offending JSON field name via itb_easy_last_mismatch_field.
 * Other status codes route through the standard last-error path. The
 * structural status code is the authoritative attribution; the field
 * name is decorative.
 */
static itb_status_t easy_set_error(int rc)
{
    return itb_internal_set_error(rc);
}

/* Saturating computation of `max(131072, n * 5 / 4 + 131072)` on
 * size_t. Caps at SIZE_MAX on overflow rather than wrapping, so the
 * first cipher call never under-allocates silently on pathologically
 * large payloads. The 128 KiB pad absorbs the residual expansion
 * from non-default barrier-fill values up to 32, where the absolute
 * ratio reaches ~1.346 around the 1 MiB payload region (the 1.25x
 * multiplier alone leaves a ~100 KiB shortfall there); it also acts
 * as the floor for very-small payloads (Triple + auth-MAC + bf=32 at
 * ptlen=1 expands to ~35 KiB). */
static size_t saturating_expansion(size_t n)
{
    size_t mul;
    if (n > (SIZE_MAX / 5)) {
        mul = SIZE_MAX;
    } else {
        mul = (n * 5) / 4;
    }
    size_t add;
    if (mul > SIZE_MAX - 131072) {
        add = SIZE_MAX;
    } else {
        add = mul + 131072;
    }
    return (add < 131072) ? 131072 : add;
}

/*
 * Wipe-on-grow contract: zero the previous buffer before freeing it
 * so the most-recent ciphertext / plaintext does not linger in heap
 * garbage between cipher calls.
 */
static itb_status_t ensure_cache(struct itb_encryptor *e, size_t need)
{
    if (e->out_cache != NULL && e->out_cache_cap >= need) {
        return ITB_OK;
    }
    /* Wipe previous bytes before freeing. */
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
    /* Documents the post-condition for static analyzers (Phase 8 Agent 5
     * surfaced a scan-build FP at the cipher_call memcpy site — `out_cache
     * != NULL` after a successful ensure_cache was not tracked across the
     * call boundary). Compiles out under -DNDEBUG. */
    assert(e->out_cache != NULL);
    return ITB_OK;
}

/* Zero + free the cache. Used by close, free, and re-init paths. */
static void wipe_cache(struct itb_encryptor *e)
{
    if (e->out_cache != NULL && e->out_cache_cap > 0) {
        memset(e->out_cache, 0, e->out_cache_cap);
    }
    free(e->out_cache);
    e->out_cache = NULL;
    e->out_cache_cap = 0;
}

/*
 * Preflight: rejects calls on closed encryptors with ITB_EASY_CLOSED
 * before any FFI call. Constructors and itb_encryptor_free do NOT
 * route through this — they manage the closed state themselves.
 */
static itb_status_t check_open(const struct itb_encryptor *e)
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

/* ------------------------------------------------------------------ */
/* String-getter context shims                                         */
/* ------------------------------------------------------------------ */

struct easy_handle_ctx { uintptr_t handle; };

static int call_easy_primitive(char *out, size_t cap, size_t *out_len, void *ctx)
{
    struct easy_handle_ctx *c = (struct easy_handle_ctx *) ctx;
    return ITB_Easy_Primitive(c->handle, out, cap, out_len);
}

static int call_easy_mac_name(char *out, size_t cap, size_t *out_len, void *ctx)
{
    struct easy_handle_ctx *c = (struct easy_handle_ctx *) ctx;
    return ITB_Easy_MACName(c->handle, out, cap, out_len);
}

struct easy_slot_ctx { uintptr_t handle; int slot; };

static int call_easy_primitive_at(char *out, size_t cap, size_t *out_len, void *ctx)
{
    struct easy_slot_ctx *c = (struct easy_slot_ctx *) ctx;
    return ITB_Easy_PrimitiveAt(c->handle, c->slot, out, cap, out_len);
}

static int call_easy_last_mismatch(char *out, size_t cap, size_t *out_len, void *ctx)
{
    (void) ctx;
    return ITB_Easy_LastMismatchField(out, cap, out_len);
}

/* ------------------------------------------------------------------ */
/* Constructors                                                        */
/* ------------------------------------------------------------------ */

/*
 * Allocates an empty wrapper struct around an established libitb
 * Easy handle. Used by all three constructors after a successful
 * ITB_Easy_New* round-trip.
 */
static itb_status_t alloc_wrapper(uintptr_t handle, itb_encryptor_t **out)
{
    itb_encryptor_t *e = (itb_encryptor_t *) malloc(sizeof(*e));
    if (e == NULL) {
        (void) ITB_Easy_Free(handle);
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }
    e->handle = handle;
    e->out_cache = NULL;
    e->out_cache_cap = 0;
    e->closed = 0;
    *out = e;
    itb_internal_reset_error();
    return ITB_OK;
}

itb_status_t itb_encryptor_new(const char *primitive, int key_bits,
                               const char *mac_name, int mode,
                               itb_encryptor_t **out)
{
    if (out == NULL) {
        return itb_internal_set_error_msg(ITB_BAD_INPUT, "out is NULL");
    }
    *out = NULL;

    /* Mode validation pre-FFI: only Single (1) or Triple (3) are
     * accepted. The Node.js binding shipped with mode = 0/1 by
     * mistake; this guard prevents the same regression here. */
    if (mode != 1 && mode != 3) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "mode must be 1 (Single) or 3 (Triple)");
    }

    /* Default-MAC override at the binding boundary: when the caller
     * passes mac_name = NULL or "" the binding picks "hmac-blake3"
     * rather than forwarding NULL through to libitb's own default
     * ("kmac256"). HMAC-BLAKE3 measures the lightest authenticated-
     * mode overhead in the Easy bench surface. */
    const char *effective_mac =
        (mac_name == NULL || mac_name[0] == '\0') ? "hmac-blake3" : mac_name;

    /* libitb's char* parameters are non-const for ABI legacy; cast
     * away const — libitb does not write through these pointers. */
    char *prim_arg = (primitive == NULL) ? NULL : (char *) primitive;
    char *mac_arg = (char *) effective_mac;

    uintptr_t handle = 0;
    int rc = ITB_Easy_New(prim_arg, key_bits, mac_arg, mode, &handle);
    if (rc != ITB_OK) {
        return easy_set_error(rc);
    }
    return alloc_wrapper(handle, out);
}

itb_status_t itb_encryptor_new_mixed(const char *prim_n,
                                     const char *prim_d,
                                     const char *prim_s,
                                     const char *prim_l,
                                     int key_bits,
                                     const char *mac_name,
                                     itb_encryptor_t **out)
{
    if (out == NULL) {
        return itb_internal_set_error_msg(ITB_BAD_INPUT, "out is NULL");
    }
    *out = NULL;
    if (prim_n == NULL || prim_d == NULL || prim_s == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "prim_n / prim_d / prim_s is NULL");
    }

    const char *effective_mac =
        (mac_name == NULL || mac_name[0] == '\0') ? "hmac-blake3" : mac_name;

    /* prim_l = NULL signals "no dedicated lockSeed primitive" — pass
     * through verbatim so libitb's own None-handling kicks in. An
     * empty-string prim_l is also treated as None (matches the Rust /
     * D bindings). */
    char *l_arg = NULL;
    if (prim_l != NULL && prim_l[0] != '\0') {
        l_arg = (char *) prim_l;
    }

    uintptr_t handle = 0;
    int rc = ITB_Easy_NewMixed(
        (char *) prim_n,
        (char *) prim_d,
        (char *) prim_s,
        l_arg,
        key_bits,
        (char *) effective_mac,
        &handle);
    if (rc != ITB_OK) {
        return easy_set_error(rc);
    }
    return alloc_wrapper(handle, out);
}

itb_status_t itb_encryptor_new_mixed3(const char *prim_n,
                                      const char *prim_d1,
                                      const char *prim_d2,
                                      const char *prim_d3,
                                      const char *prim_s1,
                                      const char *prim_s2,
                                      const char *prim_s3,
                                      const char *prim_l,
                                      int key_bits,
                                      const char *mac_name,
                                      itb_encryptor_t **out)
{
    if (out == NULL) {
        return itb_internal_set_error_msg(ITB_BAD_INPUT, "out is NULL");
    }
    *out = NULL;
    if (prim_n == NULL ||
        prim_d1 == NULL || prim_d2 == NULL || prim_d3 == NULL ||
        prim_s1 == NULL || prim_s2 == NULL || prim_s3 == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "one of the seven primitive names is NULL");
    }

    const char *effective_mac =
        (mac_name == NULL || mac_name[0] == '\0') ? "hmac-blake3" : mac_name;

    char *l_arg = NULL;
    if (prim_l != NULL && prim_l[0] != '\0') {
        l_arg = (char *) prim_l;
    }

    uintptr_t handle = 0;
    int rc = ITB_Easy_NewMixed3(
        (char *) prim_n,
        (char *) prim_d1, (char *) prim_d2, (char *) prim_d3,
        (char *) prim_s1, (char *) prim_s2, (char *) prim_s3,
        l_arg,
        key_bits,
        (char *) effective_mac,
        &handle);
    if (rc != ITB_OK) {
        return easy_set_error(rc);
    }
    return alloc_wrapper(handle, out);
}

/* ------------------------------------------------------------------ */
/* Lifecycle                                                            */
/* ------------------------------------------------------------------ */

itb_status_t itb_encryptor_close(itb_encryptor_t *e)
{
    if (e == NULL) {
        return itb_internal_set_error_msg(ITB_BAD_INPUT, "encryptor is NULL");
    }
    /* Wipe the cached output buffer regardless of close state — repeated
     * close calls keep the cache wiped without racing the Go-side close. */
    wipe_cache(e);
    if (e->closed != 0 || e->handle == 0) {
        /* Idempotent — already closed. */
        e->closed = 1;
        e->handle = 0;
        itb_internal_reset_error();
        return ITB_OK;
    }
    int rc = ITB_Easy_Close(e->handle);
    e->closed = 1;
    e->handle = 0;
    if (rc != ITB_OK) {
        return easy_set_error(rc);
    }
    itb_internal_reset_error();
    return ITB_OK;
}

void itb_encryptor_free(itb_encryptor_t *e)
{
    if (e == NULL) {
        return;
    }
    /* Wipe the cache before any libitb call so the residual plaintext /
     * ciphertext is gone even if the libitb-side free fails. */
    wipe_cache(e);
    if (e->handle != 0) {
        /* Best-effort release; errors during free are swallowed because
         * there is no path to surface them and process-shutdown ordering
         * can be unpredictable. */
        (void) ITB_Easy_Free(e->handle);
        e->handle = 0;
    }
    e->closed = 1;
    free(e);
}

/* ------------------------------------------------------------------ */
/* Cipher entry points                                                 */
/* ------------------------------------------------------------------ */

/* Direct-call buffer-convention dispatcher with a per-encryptor output
 * cache. Skips the size-probe round-trip the lower-level FFI helpers
 * use: pre-allocates output capacity from a 1.25× upper bound and
 * falls through to an explicit grow-and-retry only on the rare
 * under-shoot. The pre-allocation avoids paying for a duplicate
 * encrypt / decrypt on each call.
 *
 * The current ITB_Easy_Encrypt / ITB_Easy_Decrypt C ABI does the full
 * crypto on every call regardless of out-buffer capacity (it computes
 * the result internally, then returns ITB_BUFFER_TOO_SMALL without
 * exposing the work). So the pre-allocation is load-bearing for
 * throughput parity with native Go.
 */
typedef int (*fn_easy_cipher_t)(uintptr_t, void *, size_t,
                                void *, size_t, size_t *);

static itb_status_t cipher_call(itb_encryptor_t *e,
                                fn_easy_cipher_t fn,
                                const void *payload, size_t payload_len,
                                uint8_t **out_buf, size_t *out_len)
{
    itb_status_t open_st = check_open(e);
    if (open_st != ITB_OK) {
        return open_st;
    }
    if (out_buf == NULL || out_len == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "out_buf or out_len is NULL");
    }
    *out_buf = NULL;
    *out_len = 0;

    /* 1.25× + 4 KiB headroom comfortably exceeds the 1.155 max
     * expansion factor observed across the primitive / mode /
     * nonce-bits matrix; floor at 4 KiB so the very-small payload
     * case still gets a usable buffer. Saturating arithmetic guards
     * against size_t overflow on giant inputs. */
    size_t cap = saturating_expansion(payload_len);
    itb_status_t alloc_st = ensure_cache(e, cap);
    if (alloc_st != ITB_OK) {
        return alloc_st;
    }

    void *in_ptr = (payload_len == 0) ? NULL : (void *) payload;

    size_t written = 0;
    int rc = fn(e->handle,
                in_ptr, payload_len,
                e->out_cache, e->out_cache_cap,
                &written);
    if (rc == ITB_BUFFER_TOO_SMALL) {
        /* Pre-allocation was too tight (extremely rare given the 1.25×
         * safety margin) — grow exactly to the required size and
         * retry. The first call already paid for the underlying
         * crypto via the current C ABI's full-encrypt-on-every-call
         * contract, so the retry runs the work again; this is
         * strictly the fallback path and not the hot loop. */
        size_t need = written;
        alloc_st = ensure_cache(e, need);
        if (alloc_st != ITB_OK) {
            return alloc_st;
        }
        rc = fn(e->handle,
                in_ptr, payload_len,
                e->out_cache, e->out_cache_cap,
                &written);
    }
    if (rc != ITB_OK) {
        return easy_set_error(rc);
    }

    /* Hand the caller a fresh malloc'd copy. The internal cache stays
     * resident as the FFI write target so subsequent calls skip the
     * libitb size-probe round-trip and reuse the pre-grown buffer.
     * Returning a user-owned copy (rather than a pointer into the
     * cache) avoids a subtle aliasing footgun: a caller passing the
     * previous-call's output back as input to a second call on the
     * same encryptor would otherwise see the input source overwritten
     * by the FFI write target mid-call (libitb's encrypt / decrypt
     * does not assume non-overlap of in / out buffers). */
    if (written == 0) {
        itb_internal_reset_error();
        return ITB_OK;
    }
    uint8_t *user_buf = (uint8_t *) malloc(written);
    if (user_buf == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }
    memcpy(user_buf, e->out_cache, written);
    *out_buf = user_buf;
    *out_len = written;
    itb_internal_reset_error();
    return ITB_OK;
}

itb_status_t itb_encryptor_encrypt(itb_encryptor_t *e,
                                   const void *plaintext, size_t plaintext_len,
                                   uint8_t **out_buf, size_t *out_len)
{
    return cipher_call(e, ITB_Easy_Encrypt,
                       plaintext, plaintext_len, out_buf, out_len);
}

itb_status_t itb_encryptor_decrypt(itb_encryptor_t *e,
                                   const void *ciphertext, size_t ciphertext_len,
                                   uint8_t **out_buf, size_t *out_len)
{
    return cipher_call(e, ITB_Easy_Decrypt,
                       ciphertext, ciphertext_len, out_buf, out_len);
}

itb_status_t itb_encryptor_encrypt_auth(itb_encryptor_t *e,
                                        const void *plaintext, size_t plaintext_len,
                                        uint8_t **out_buf, size_t *out_len)
{
    return cipher_call(e, ITB_Easy_EncryptAuth,
                       plaintext, plaintext_len, out_buf, out_len);
}

itb_status_t itb_encryptor_decrypt_auth(itb_encryptor_t *e,
                                        const void *ciphertext, size_t ciphertext_len,
                                        uint8_t **out_buf, size_t *out_len)
{
    return cipher_call(e, ITB_Easy_DecryptAuth,
                       ciphertext, ciphertext_len, out_buf, out_len);
}

/* ------------------------------------------------------------------ */
/* Per-instance configuration setters                                  */
/* ------------------------------------------------------------------ */

#define EASY_SETTER(fn_name, ffi_fn)                                           \
    itb_status_t fn_name(itb_encryptor_t *e, int n) {                          \
        itb_status_t open_st = check_open(e);                                  \
        if (open_st != ITB_OK) return open_st;                                 \
        int rc = ffi_fn(e->handle, n);                                         \
        if (rc != ITB_OK) return easy_set_error(rc);                           \
        itb_internal_reset_error();                                            \
        return ITB_OK;                                                         \
    }

EASY_SETTER(itb_encryptor_set_nonce_bits,   ITB_Easy_SetNonceBits)
EASY_SETTER(itb_encryptor_set_barrier_fill, ITB_Easy_SetBarrierFill)
EASY_SETTER(itb_encryptor_set_bit_soup,     ITB_Easy_SetBitSoup)
EASY_SETTER(itb_encryptor_set_lock_soup,    ITB_Easy_SetLockSoup)
EASY_SETTER(itb_encryptor_set_lock_batch,   ITB_Easy_SetLockBatch)
EASY_SETTER(itb_encryptor_set_lock_seed,    ITB_Easy_SetLockSeed)
EASY_SETTER(itb_encryptor_set_chunk_size,   ITB_Easy_SetChunkSize)

#undef EASY_SETTER

/* ------------------------------------------------------------------ */
/* Read-only field accessors                                           */
/* ------------------------------------------------------------------ */

itb_status_t itb_encryptor_primitive(const itb_encryptor_t *e,
                                     char *out, size_t cap, size_t *out_len)
{
    itb_status_t open_st = check_open(e);
    if (open_st != ITB_OK) return open_st;
    struct easy_handle_ctx ctx = { e->handle };
    return itb_internal_read_string(call_easy_primitive, &ctx, out, cap, out_len);
}

itb_status_t itb_encryptor_mac_name(const itb_encryptor_t *e,
                                    char *out, size_t cap, size_t *out_len)
{
    itb_status_t open_st = check_open(e);
    if (open_st != ITB_OK) return open_st;
    struct easy_handle_ctx ctx = { e->handle };
    return itb_internal_read_string(call_easy_mac_name, &ctx, out, cap, out_len);
}

itb_status_t itb_encryptor_primitive_at(const itb_encryptor_t *e, int slot,
                                        char *out, size_t cap, size_t *out_len)
{
    itb_status_t open_st = check_open(e);
    if (open_st != ITB_OK) return open_st;
    struct easy_slot_ctx ctx = { e->handle, slot };
    return itb_internal_read_string(call_easy_primitive_at, &ctx, out, cap, out_len);
}

#define EASY_INT_GETTER(fn_name, ffi_fn)                                       \
    itb_status_t fn_name(const itb_encryptor_t *e, int *out_value) {           \
        itb_status_t open_st = check_open(e);                                  \
        if (open_st != ITB_OK) return open_st;                                 \
        if (out_value == NULL) {                                               \
            return itb_internal_set_error_msg(ITB_BAD_INPUT, "out is NULL");   \
        }                                                                      \
        int st = ITB_OK;                                                       \
        int v = ffi_fn(e->handle, &st);                                        \
        if (st != ITB_OK) return easy_set_error(st);                           \
        *out_value = v;                                                        \
        itb_internal_reset_error();                                            \
        return ITB_OK;                                                         \
    }

EASY_INT_GETTER(itb_encryptor_key_bits,    ITB_Easy_KeyBits)
EASY_INT_GETTER(itb_encryptor_mode,        ITB_Easy_Mode)
EASY_INT_GETTER(itb_encryptor_seed_count,  ITB_Easy_SeedCount)
EASY_INT_GETTER(itb_encryptor_nonce_bits,  ITB_Easy_NonceBits)
EASY_INT_GETTER(itb_encryptor_header_size, ITB_Easy_HeaderSize)

#undef EASY_INT_GETTER

itb_status_t itb_encryptor_has_prf_keys(const itb_encryptor_t *e, int *out_value)
{
    itb_status_t open_st = check_open(e);
    if (open_st != ITB_OK) return open_st;
    if (out_value == NULL) {
        return itb_internal_set_error_msg(ITB_BAD_INPUT, "out is NULL");
    }
    int st = ITB_OK;
    int v = ITB_Easy_HasPRFKeys(e->handle, &st);
    if (st != ITB_OK) return easy_set_error(st);
    *out_value = (v != 0) ? 1 : 0;
    itb_internal_reset_error();
    return ITB_OK;
}

itb_status_t itb_encryptor_is_mixed(const itb_encryptor_t *e, int *out_value)
{
    itb_status_t open_st = check_open(e);
    if (open_st != ITB_OK) return open_st;
    if (out_value == NULL) {
        return itb_internal_set_error_msg(ITB_BAD_INPUT, "out is NULL");
    }
    int st = ITB_OK;
    int v = ITB_Easy_IsMixed(e->handle, &st);
    if (st != ITB_OK) return easy_set_error(st);
    *out_value = (v != 0) ? 1 : 0;
    itb_internal_reset_error();
    return ITB_OK;
}

itb_status_t itb_encryptor_parse_chunk_len(const itb_encryptor_t *e,
                                           const void *header, size_t header_len,
                                           size_t *out_chunk_len)
{
    itb_status_t open_st = check_open(e);
    if (open_st != ITB_OK) return open_st;
    if (out_chunk_len == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "out_chunk_len is NULL");
    }
    *out_chunk_len = 0;
    void *hdr = (header_len == 0) ? NULL : (void *) header;
    int rc = ITB_Easy_ParseChunkLen(e->handle, hdr, header_len, out_chunk_len);
    if (rc != ITB_OK) {
        return easy_set_error(rc);
    }
    itb_internal_reset_error();
    return ITB_OK;
}

/* ------------------------------------------------------------------ */
/* Material getters (defensive copies)                                  */
/* ------------------------------------------------------------------ */

itb_status_t itb_encryptor_seed_components(const itb_encryptor_t *e, int slot,
                                           uint64_t *out, size_t cap_count,
                                           size_t *out_count)
{
    itb_status_t open_st = check_open(e);
    if (open_st != ITB_OK) return open_st;
    if (out_count == NULL) {
        return itb_internal_set_error_msg(ITB_BAD_INPUT, "out_count is NULL");
    }
    *out_count = 0;

    int needed = 0;
    int rc = ITB_Easy_SeedComponents(e->handle, slot, NULL, 0, &needed);
    if (rc == ITB_OK && needed == 0) {
        itb_internal_reset_error();
        return ITB_OK;
    }
    if (rc != ITB_BUFFER_TOO_SMALL) {
        return easy_set_error(rc);
    }
    if (needed < 0) {
        return itb_internal_set_error_msg(
            ITB_INTERNAL, "ITB_Easy_SeedComponents reported negative size");
    }
    if (out == NULL || cap_count < (size_t) needed) {
        *out_count = (size_t) needed;
        return itb_internal_set_error(ITB_BUFFER_TOO_SMALL);
    }
    /* Guard the cast to int on libitb's count argument — needed is
     * already int-bounded by the prior `< 0` check, but cap_count is a
     * caller-supplied size_t that could exceed INT_MAX. */
    if (cap_count > (size_t) 0x7FFFFFFF) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "cap_count exceeds INT32_MAX");
    }

    int written = 0;
    rc = ITB_Easy_SeedComponents(e->handle, slot, out, (int) cap_count, &written);
    if (rc != ITB_OK) {
        return easy_set_error(rc);
    }
    if (written < 0) {
        return itb_internal_set_error_msg(
            ITB_INTERNAL, "ITB_Easy_SeedComponents reported negative size");
    }
    *out_count = (size_t) written;
    itb_internal_reset_error();
    return ITB_OK;
}

itb_status_t itb_encryptor_prf_key(const itb_encryptor_t *e, int slot,
                                   uint8_t *out, size_t cap, size_t *out_len)
{
    itb_status_t open_st = check_open(e);
    if (open_st != ITB_OK) return open_st;
    if (out_len == NULL) {
        return itb_internal_set_error_msg(ITB_BAD_INPUT, "out_len is NULL");
    }
    *out_len = 0;

    /* Probe pattern: zero-length key → ITB_OK + need=0 (e.g. siphash24);
     * non-zero length → ITB_BUFFER_TOO_SMALL with need carrying the
     * required size. ITB_BAD_INPUT is reserved for out-of-range slot
     * or no-fixed-key primitive. */
    size_t need = 0;
    int rc = ITB_Easy_PRFKey(e->handle, slot, NULL, 0, &need);
    if (rc == ITB_OK && need == 0) {
        itb_internal_reset_error();
        return ITB_OK;
    }
    if (rc != ITB_BUFFER_TOO_SMALL) {
        return easy_set_error(rc);
    }
    if (out == NULL || cap < need) {
        *out_len = need;
        return itb_internal_set_error(ITB_BUFFER_TOO_SMALL);
    }

    size_t written = 0;
    rc = ITB_Easy_PRFKey(e->handle, slot, out, cap, &written);
    if (rc != ITB_OK) {
        return easy_set_error(rc);
    }
    *out_len = written;
    itb_internal_reset_error();
    return ITB_OK;
}

itb_status_t itb_encryptor_mac_key(const itb_encryptor_t *e,
                                   uint8_t *out, size_t cap, size_t *out_len)
{
    itb_status_t open_st = check_open(e);
    if (open_st != ITB_OK) return open_st;
    if (out_len == NULL) {
        return itb_internal_set_error_msg(ITB_BAD_INPUT, "out_len is NULL");
    }
    *out_len = 0;

    size_t need = 0;
    int rc = ITB_Easy_MACKey(e->handle, NULL, 0, &need);
    if (rc == ITB_OK && need == 0) {
        itb_internal_reset_error();
        return ITB_OK;
    }
    if (rc != ITB_BUFFER_TOO_SMALL) {
        return easy_set_error(rc);
    }
    if (out == NULL || cap < need) {
        *out_len = need;
        return itb_internal_set_error(ITB_BUFFER_TOO_SMALL);
    }

    size_t written = 0;
    rc = ITB_Easy_MACKey(e->handle, out, cap, &written);
    if (rc != ITB_OK) {
        return easy_set_error(rc);
    }
    *out_len = written;
    itb_internal_reset_error();
    return ITB_OK;
}

/* ------------------------------------------------------------------ */
/* Persistence                                                         */
/* ------------------------------------------------------------------ */

itb_status_t itb_encryptor_export(const itb_encryptor_t *e,
                                  uint8_t **out_buf, size_t *out_len)
{
    if (out_buf == NULL || out_len == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "out_buf or out_len is NULL");
    }
    *out_buf = NULL;
    *out_len = 0;
    itb_status_t open_st = check_open(e);
    if (open_st != ITB_OK) return open_st;

    size_t need = 0;
    int rc = ITB_Easy_Export(e->handle, NULL, 0, &need);
    if (rc == ITB_OK && need == 0) {
        itb_internal_reset_error();
        return ITB_OK;
    }
    if (rc != ITB_BUFFER_TOO_SMALL) {
        return easy_set_error(rc);
    }

    uint8_t *buf = (uint8_t *) malloc(need);
    if (buf == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }

    size_t written = 0;
    rc = ITB_Easy_Export(e->handle, buf, need, &written);
    if (rc != ITB_OK) {
        free(buf);
        return easy_set_error(rc);
    }
    *out_buf = buf;
    *out_len = written;
    itb_internal_reset_error();
    return ITB_OK;
}

itb_status_t itb_encryptor_import(itb_encryptor_t *e,
                                  const void *blob, size_t blob_len)
{
    itb_status_t open_st = check_open(e);
    if (open_st != ITB_OK) return open_st;
    if (blob_len > 0 && blob == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "blob_len > 0 but blob is NULL");
    }
    void *blob_ptr = (blob_len == 0) ? NULL : (void *) blob;
    int rc = ITB_Easy_Import(e->handle, blob_ptr, blob_len);
    if (rc != ITB_OK) {
        return easy_set_error(rc);
    }
    itb_internal_reset_error();
    return ITB_OK;
}

/* ------------------------------------------------------------------ */
/* Free functions: peek + last-mismatch                                */
/* ------------------------------------------------------------------ */

itb_status_t itb_easy_peek_config(const void *blob, size_t blob_len,
                                  char *prim_out, size_t prim_cap, size_t *prim_len,
                                  int *key_bits_out, int *mode_out,
                                  char *mac_out, size_t mac_cap, size_t *mac_len)
{
    if (prim_len == NULL || mac_len == NULL ||
        key_bits_out == NULL || mode_out == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "out parameter is NULL");
    }
    if (blob_len > 0 && blob == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "blob_len > 0 but blob is NULL");
    }
    *prim_len = 0;
    *mac_len = 0;
    *key_bits_out = 0;
    *mode_out = 0;
    if (prim_out != NULL && prim_cap >= 1) prim_out[0] = '\0';
    if (mac_out != NULL && mac_cap >= 1)   mac_out[0] = '\0';

    void *blob_ptr = (blob_len == 0) ? NULL : (void *) blob;

    /* Probe both string sizes first (libitb counts the trailing NUL in
     * each *_len). */
    size_t need_prim = 0, need_mac = 0;
    int rc = ITB_Easy_PeekConfig(blob_ptr, blob_len,
                                 NULL, 0, &need_prim,
                                 key_bits_out, mode_out,
                                 NULL, 0, &need_mac);
    if (rc != ITB_OK && rc != ITB_BUFFER_TOO_SMALL) {
        return easy_set_error(rc);
    }

    /* Empty-string short-circuit on either field (rare — both names
     * are populated in every well-formed v1 blob). */
    if (need_prim <= 1 && need_mac <= 1) {
        itb_internal_reset_error();
        return ITB_OK;
    }

    /* Caller may want both string sizes reported even when only one
     * buffer is too small; surface ITB_BUFFER_TOO_SMALL with visible
     * lengths (NUL-stripped) when either buffer falls short. */
    int short_prim = 0, short_mac = 0;
    if (need_prim > 1) {
        if (prim_out == NULL || prim_cap < need_prim) {
            *prim_len = need_prim - 1;
            short_prim = 1;
        }
    }
    if (need_mac > 1) {
        if (mac_out == NULL || mac_cap < need_mac) {
            *mac_len = need_mac - 1;
            short_mac = 1;
        }
    }
    if (short_prim || short_mac) {
        return itb_internal_set_error(ITB_BUFFER_TOO_SMALL);
    }

    /* Both buffers are sufficient — read into them. */
    char *prim_arg = (need_prim <= 1) ? NULL : prim_out;
    size_t prim_arg_cap = (need_prim <= 1) ? 0 : prim_cap;
    char *mac_arg = (need_mac <= 1) ? NULL : mac_out;
    size_t mac_arg_cap = (need_mac <= 1) ? 0 : mac_cap;

    size_t got_prim = 0, got_mac = 0;
    rc = ITB_Easy_PeekConfig(blob_ptr, blob_len,
                             prim_arg, prim_arg_cap, &got_prim,
                             key_bits_out, mode_out,
                             mac_arg, mac_arg_cap, &got_mac);
    if (rc != ITB_OK) {
        return easy_set_error(rc);
    }

    /* NUL-strip uniformly. libitb counts trailing NUL in got_*; report
     * visible length and ensure the caller's buffer is NUL-terminated
     * at the visible offset. */
    if (got_prim == 0) {
        *prim_len = 0;
        if (prim_out != NULL && prim_cap >= 1) prim_out[0] = '\0';
    } else {
        size_t v = got_prim - 1;
        if (prim_out != NULL) {
            if (v < prim_cap) prim_out[v] = '\0';
            else if (prim_cap >= 1) prim_out[prim_cap - 1] = '\0';
        }
        *prim_len = v;
    }
    if (got_mac == 0) {
        *mac_len = 0;
        if (mac_out != NULL && mac_cap >= 1) mac_out[0] = '\0';
    } else {
        size_t v = got_mac - 1;
        if (mac_out != NULL) {
            if (v < mac_cap) mac_out[v] = '\0';
            else if (mac_cap >= 1) mac_out[mac_cap - 1] = '\0';
        }
        *mac_len = v;
    }
    itb_internal_reset_error();
    return ITB_OK;
}

itb_status_t itb_easy_last_mismatch_field(char *out, size_t cap, size_t *out_len)
{
    return itb_internal_read_string(call_easy_last_mismatch, NULL,
                                    out, cap, out_len);
}
