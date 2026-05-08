/*
 * registry.c — library version, hash + MAC catalogue, process-wide
 * knobs, and stream-header helpers.
 *
 * Mirrors Rust src/registry.rs / D src/itb/registry.d. The set_* / get_*
 * knobs below are process-global libitb state — calls are NOT thread-
 * safe; serialise against concurrent cipher invocations.
 */
#include <stddef.h>

#include "internal.h"

/* ------------------------------------------------------------------ */
/* String-getter context shims                                          */
/* ------------------------------------------------------------------ */

/* Forwards itb_internal_read_string's (out, cap, out_len, ctx) shape to
 * libitb's (out, cap, out_len) signature for entry points that take no
 * extra index. */
static int call_version(char *out, size_t cap, size_t *out_len, void *ctx)
{
    (void) ctx;
    return ITB_Version(out, cap, out_len);
}

itb_status_t itb_version(char *out, size_t cap, size_t *out_len)
{
    return itb_internal_read_string(call_version, NULL, out, cap, out_len);
}

int itb_max_key_bits(void)  { return ITB_MaxKeyBits(); }
int itb_channels(void)      { return ITB_Channels();   }
int itb_header_size(void)   { return ITB_HeaderSize(); }

itb_status_t itb_parse_chunk_len(const void *header, size_t header_len,
                                 size_t *out_chunk_len)
{
    if (out_chunk_len == NULL) {
        return itb_internal_set_error_msg(ITB_BAD_INPUT, "out_chunk_len is NULL");
    }
    *out_chunk_len = 0;
    int rc = ITB_ParseChunkLen((void *) header, header_len, out_chunk_len);
    if (rc != ITB_OK) {
        return itb_internal_set_error(rc);
    }
    itb_internal_reset_error();
    return ITB_OK;
}

/* ------------------------------------------------------------------ */
/* Hash registry                                                       */
/* ------------------------------------------------------------------ */

int itb_hash_count(void) { return ITB_HashCount(); }

struct hash_name_ctx { int i; };

static int call_hash_name(char *out, size_t cap, size_t *out_len, void *ctx)
{
    struct hash_name_ctx *c = (struct hash_name_ctx *) ctx;
    return ITB_HashName(c->i, out, cap, out_len);
}

itb_status_t itb_hash_name(int i, char *out, size_t cap, size_t *out_len)
{
    struct hash_name_ctx ctx = { i };
    return itb_internal_read_string(call_hash_name, &ctx, out, cap, out_len);
}

int itb_hash_width(int i) { return ITB_HashWidth(i); }

/* ------------------------------------------------------------------ */
/* MAC registry                                                        */
/* ------------------------------------------------------------------ */

int itb_mac_count(void) { return ITB_MACCount(); }

struct mac_name_ctx { int i; };

static int call_mac_name(char *out, size_t cap, size_t *out_len, void *ctx)
{
    struct mac_name_ctx *c = (struct mac_name_ctx *) ctx;
    return ITB_MACName(c->i, out, cap, out_len);
}

itb_status_t itb_mac_name(int i, char *out, size_t cap, size_t *out_len)
{
    struct mac_name_ctx ctx = { i };
    return itb_internal_read_string(call_mac_name, &ctx, out, cap, out_len);
}

int itb_mac_key_size(int i)      { return ITB_MACKeySize(i);     }
int itb_mac_tag_size(int i)      { return ITB_MACTagSize(i);     }
int itb_mac_min_key_bytes(int i) { return ITB_MACMinKeyBytes(i); }

/* ------------------------------------------------------------------ */
/* Process-wide knobs                                                  */
/* ------------------------------------------------------------------ */
/*
 * Each setter forwards to libitb after resetting the thread-local
 * last-error so a successful set leaves the diagnostic in a known
 * "no error" state. Getters never fail at the libitb layer (they
 * return the current value as int) — exposed as plain `int` returns
 * matching the cross-binding pattern.
 */

#define ITB_SET_INT(name, c_fn)                                                \
    itb_status_t name(int v) {                                                 \
        int rc = c_fn(v);                                                      \
        if (rc != ITB_OK) return itb_internal_set_error(rc);                   \
        itb_internal_reset_error();                                            \
        return ITB_OK;                                                         \
    }

ITB_SET_INT(itb_set_bit_soup,     ITB_SetBitSoup)
ITB_SET_INT(itb_set_lock_soup,    ITB_SetLockSoup)
ITB_SET_INT(itb_set_max_workers,  ITB_SetMaxWorkers)
ITB_SET_INT(itb_set_nonce_bits,   ITB_SetNonceBits)
ITB_SET_INT(itb_set_barrier_fill, ITB_SetBarrierFill)

#undef ITB_SET_INT

int itb_get_bit_soup(void)     { return ITB_GetBitSoup();     }
int itb_get_lock_soup(void)    { return ITB_GetLockSoup();    }
int itb_get_max_workers(void)  { return ITB_GetMaxWorkers();  }
int itb_get_nonce_bits(void)   { return ITB_GetNonceBits();   }
int itb_get_barrier_fill(void) { return ITB_GetBarrierFill(); }
