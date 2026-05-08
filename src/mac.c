/*
 * mac.c — keyed MAC handle wrapper.
 *
 * Mirrors Rust src/mac.rs / D src/itb/mac.d.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

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

itb_status_t itb_mac_new(const char *mac_name,
                         const uint8_t *key, size_t key_len,
                         itb_mac_t **out)
{
    if (out == NULL) {
        return itb_internal_set_error_msg(ITB_BAD_INPUT, "out is NULL");
    }
    *out = NULL;
    if (mac_name == NULL) {
        return itb_internal_set_error_msg(ITB_BAD_INPUT, "mac_name is NULL");
    }
    if (key_len > 0 && key == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "key_len > 0 but key is NULL");
    }

    uintptr_t handle = 0;
    int rc = ITB_NewMAC((char *) mac_name,
                        (void *) key, /* libitb takes non-const for ABI legacy */
                        key_len,
                        &handle);
    if (rc != ITB_OK) {
        return itb_internal_set_error(rc);
    }

    itb_mac_t *m = (itb_mac_t *) malloc(sizeof(*m));
    if (m == NULL) {
        ITB_FreeMAC(handle);
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }
    m->handle = handle;
    m->name = dup_cstr(mac_name);
    if (m->name == NULL) {
        ITB_FreeMAC(handle);
        free(m);
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }

    *out = m;
    itb_internal_reset_error();
    return ITB_OK;
}

void itb_mac_free(itb_mac_t *m)
{
    if (m == NULL) {
        return;
    }
    if (m->handle != 0) {
        (void) ITB_FreeMAC(m->handle);
        m->handle = 0;
    }
    free(m->name);
    m->name = NULL;
    free(m);
}
