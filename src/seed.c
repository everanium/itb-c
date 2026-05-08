/*
 * seed.c — Seed handle wrapper.
 *
 * Mirrors Rust src/seed.rs / D src/itb/seed.d. The opaque struct
 * itb_seed_t carries the libitb uintptr_t handle plus a malloc'd copy
 * of the canonical hash name (so the wrapper never re-derives it from
 * libitb after construction).
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

/* Internal helper: malloc'd duplicate of a NUL-terminated input. */
static char *dup_cstr(const char *s)
{
    if (s == NULL) {
        return NULL;
    }
    size_t n = strlen(s);
    char *p = (char *) malloc(n + 1);
    if (p == NULL) {
        return NULL;
    }
    memcpy(p, s, n);
    p[n] = '\0';
    return p;
}

itb_status_t itb_seed_new(const char *hash_name, int key_bits,
                          itb_seed_t **out)
{
    if (out == NULL) {
        return itb_internal_set_error_msg(ITB_BAD_INPUT, "out is NULL");
    }
    *out = NULL;
    if (hash_name == NULL) {
        return itb_internal_set_error_msg(ITB_BAD_INPUT, "hash_name is NULL");
    }

    uintptr_t handle = 0;
    /* libitb's signature takes char* (non-const) for legacy reasons;
     * cast away const — libitb does not write through this pointer. */
    int rc = ITB_NewSeed((char *) hash_name, key_bits, &handle);
    if (rc != ITB_OK) {
        return itb_internal_set_error(rc);
    }

    itb_seed_t *s = (itb_seed_t *) malloc(sizeof(*s));
    if (s == NULL) {
        ITB_FreeSeed(handle);
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }
    s->handle = handle;
    s->hash_name = dup_cstr(hash_name);
    if (s->hash_name == NULL) {
        ITB_FreeSeed(handle);
        free(s);
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }

    *out = s;
    itb_internal_reset_error();
    return ITB_OK;
}

itb_status_t itb_seed_from_components(const char *hash_name,
                                      const uint64_t *components,
                                      size_t components_len,
                                      const uint8_t *hash_key,
                                      size_t hash_key_len,
                                      itb_seed_t **out)
{
    if (out == NULL) {
        return itb_internal_set_error_msg(ITB_BAD_INPUT, "out is NULL");
    }
    *out = NULL;
    if (hash_name == NULL) {
        return itb_internal_set_error_msg(ITB_BAD_INPUT, "hash_name is NULL");
    }
    if (components_len > 0 && components == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "components_len > 0 but components is NULL");
    }
    if (hash_key_len > 0 && hash_key == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "hash_key_len > 0 but hash_key is NULL");
    }
    /* libitb's int parameters cap counts at INT32_MAX; sanitise here. */
    if (components_len > (size_t) 0x7FFFFFFF) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "components_len exceeds INT32_MAX");
    }
    if (hash_key_len > (size_t) 0x7FFFFFFF) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "hash_key_len exceeds INT32_MAX");
    }

    uintptr_t handle = 0;
    int rc = ITB_NewSeedFromComponents(
        (char *) hash_name,
        (uint64_t *) components, /* libitb takes non-const for ABI legacy */
        (int) components_len,
        (uint8_t *) hash_key,
        (int) hash_key_len,
        &handle);
    if (rc != ITB_OK) {
        return itb_internal_set_error(rc);
    }

    itb_seed_t *s = (itb_seed_t *) malloc(sizeof(*s));
    if (s == NULL) {
        ITB_FreeSeed(handle);
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }
    s->handle = handle;
    s->hash_name = dup_cstr(hash_name);
    if (s->hash_name == NULL) {
        ITB_FreeSeed(handle);
        free(s);
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }

    *out = s;
    itb_internal_reset_error();
    return ITB_OK;
}

void itb_seed_free(itb_seed_t *s)
{
    if (s == NULL) {
        return;
    }
    if (s->handle != 0) {
        /* Best-effort release; errors during free are swallowed because
         * there is no path to surface them and process-shutdown ordering
         * can be unpredictable. */
        (void) ITB_FreeSeed(s->handle);
        s->handle = 0;
    }
    free(s->hash_name);
    s->hash_name = NULL;
    free(s);
}

itb_status_t itb_seed_width(const itb_seed_t *s, int *out_width)
{
    if (s == NULL || out_width == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "seed or out_width is NULL");
    }
    int status = ITB_OK;
    int w = ITB_SeedWidth(s->handle, &status);
    if (status != ITB_OK) {
        return itb_internal_set_error(status);
    }
    *out_width = w;
    itb_internal_reset_error();
    return ITB_OK;
}

/* Context shim for read_string. */
struct seed_hash_name_ctx { uintptr_t handle; };

static int call_seed_hash_name(char *out, size_t cap, size_t *out_len, void *ctx)
{
    struct seed_hash_name_ctx *c = (struct seed_hash_name_ctx *) ctx;
    return ITB_SeedHashName(c->handle, out, cap, out_len);
}

itb_status_t itb_seed_hash_name(const itb_seed_t *s,
                                char *out, size_t cap, size_t *out_len)
{
    if (s == NULL) {
        return itb_internal_set_error_msg(ITB_BAD_INPUT, "seed is NULL");
    }
    struct seed_hash_name_ctx ctx = { s->handle };
    return itb_internal_read_string(call_seed_hash_name, &ctx, out, cap, out_len);
}

itb_status_t itb_seed_hash_key(const itb_seed_t *s,
                               uint8_t *out, size_t cap, size_t *out_len)
{
    if (s == NULL || out_len == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "seed or out_len is NULL");
    }
    *out_len = 0;

    /* Probe libitb. */
    size_t need = 0;
    int rc = ITB_GetSeedHashKey(s->handle, NULL, 0, &need);
    /* Empty-key short-circuit (siphash24): probe returns OK with need=0. */
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
    rc = ITB_GetSeedHashKey(s->handle, out, cap, &written);
    if (rc != ITB_OK) {
        return itb_internal_set_error(rc);
    }
    *out_len = written;
    itb_internal_reset_error();
    return ITB_OK;
}

itb_status_t itb_seed_components(const itb_seed_t *s,
                                 uint64_t *out, size_t cap_count,
                                 size_t *out_count)
{
    if (s == NULL || out_count == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "seed or out_count is NULL");
    }
    *out_count = 0;

    /* Probe libitb. */
    int needed = 0;
    int rc = ITB_GetSeedComponents(s->handle, NULL, 0, &needed);
    if (rc != ITB_BUFFER_TOO_SMALL) {
        if (rc == ITB_OK && needed == 0) {
            itb_internal_reset_error();
            return ITB_OK;
        }
        return itb_internal_set_error(rc);
    }
    if (needed < 0) {
        return itb_internal_set_error_msg(
            ITB_INTERNAL, "ITB_GetSeedComponents reported negative size");
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
    rc = ITB_GetSeedComponents(s->handle, out, (int) cap_count, &written);
    if (rc != ITB_OK) {
        return itb_internal_set_error(rc);
    }
    if (written < 0) {
        return itb_internal_set_error_msg(
            ITB_INTERNAL, "ITB_GetSeedComponents reported negative size");
    }
    *out_count = (size_t) written;
    itb_internal_reset_error();
    return ITB_OK;
}

itb_status_t itb_seed_attach_lock_seed(itb_seed_t *noise,
                                       const itb_seed_t *lock_seed)
{
    if (noise == NULL || lock_seed == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "seed handle is NULL");
    }
    int rc = ITB_AttachLockSeed(noise->handle, lock_seed->handle);
    if (rc != ITB_OK) {
        return itb_internal_set_error(rc);
    }
    itb_internal_reset_error();
    return ITB_OK;
}
