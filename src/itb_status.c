/*
 * itb_status.c — status labels, last-error fetch, runtime knobs, and
 * the diagnostic registry iteration for CLI tooling.
 */

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

/* ------------------------------------------------------------------ */
/* Status → label table                                                */
/* ------------------------------------------------------------------ */

const char *itb_status_str(itb_status status)
{
    switch (status) {
    case ITB_STATUS_OK:                   return "ok";
    case ITB_STATUS_BAD_HASH:             return "unknown hash name";
    case ITB_STATUS_BAD_KEY_BITS:         return "invalid key bits";
    case ITB_STATUS_BAD_HANDLE:           return "invalid handle";
    case ITB_STATUS_BAD_INPUT:            return "invalid input";
    case ITB_STATUS_BUFFER_TOO_SMALL:     return "output buffer too small";
    case ITB_STATUS_ENCRYPT_FAILED:       return "encrypt failed";
    case ITB_STATUS_DECRYPT_FAILED:       return "decrypt failed";
    case ITB_STATUS_SEED_WIDTH_MIX:       return "seed width mismatch";
    case ITB_STATUS_BAD_MAC:              return "unknown MAC name or invalid MAC handle";
    case ITB_STATUS_MAC_FAILURE:          return "MAC verification failed";
    case ITB_STATUS_RESERVED_11:
    case ITB_STATUS_RESERVED_12:
    case ITB_STATUS_RESERVED_13:
    case ITB_STATUS_RESERVED_14:
    case ITB_STATUS_RESERVED_15:
    case ITB_STATUS_RESERVED_16:
    case ITB_STATUS_RESERVED_17:          return "reserved status";
    case ITB_STATUS_BLOB_MODE_MISMATCH:   return "blob mode mismatch";
    case ITB_STATUS_BLOB_MALFORMED:       return "malformed state blob";
    case ITB_STATUS_BLOB_VERSION_TOO_NEW: return "blob version too new";
    case ITB_STATUS_BLOB_TOO_MANY_OPTS:   return "too many blob export opts";
    case ITB_STATUS_STREAM_TRUNCATED:     return "stream truncated before terminator";
    case ITB_STATUS_STREAM_AFTER_FINAL:   return "stream chunk after terminator";
    case ITB_STATUS_TRIPLE_CLOSED:        return "Triple Pipeline is closed";
    case ITB_STATUS_PROFILE_EXISTS:       return "profile name already registered";
    case ITB_STATUS_INTERNAL:             return "internal error";
    }
    return "unknown status";
}

itb_status itb_internal_status(int rc)
{
    switch (rc) {
    case 0: case 1: case 2: case 3: case 4: case 5: case 6: case 7:
    case 8: case 9: case 10: case 11: case 12: case 13: case 14:
    case 15: case 16: case 17: case 19: case 20: case 21: case 22:
    case 23: case 24: case 25: case 26: case 99:
        return (itb_status)rc;
    default:
        return ITB_STATUS_INTERNAL;
    }
}

/* ------------------------------------------------------------------ */
/* String getters over the (out, cap, *out_len) libitb contract        */
/* ------------------------------------------------------------------ */

/* Thread-local snapshot buffers. The libitb diagnostics are short
 * sentences; 2 KiB covers every message the Go side emits. */
#define ITB_ERRBUF_CAP ((size_t)2048)
static _Thread_local char g_last_error[ITB_ERRBUF_CAP];
static _Thread_local char g_version[64];
static _Thread_local char g_hash_name[128];

const char *itb_last_error(void)
{
    size_t need = 0;
    g_last_error[0] = '\0';
    int rc = ITB_LastError(g_last_error, sizeof(g_last_error), &need);
    if (rc != (int)ITB_STATUS_OK) {
        /* BUFFER_TOO_SMALL (diagnostic > 2 KiB) or a load failure —
         * fall back to the empty string rather than partial bytes. */
        g_last_error[0] = '\0';
    }
    return g_last_error;
}

const char *itb_version(void)
{
    size_t need = 0;
    g_version[0] = '\0';
    int rc = ITB_Version(g_version, sizeof(g_version), &need);
    if (rc != (int)ITB_STATUS_OK) {
        return NULL;
    }
    return g_version;
}

/* ------------------------------------------------------------------ */
/* Go runtime knobs                                                    */
/* ------------------------------------------------------------------ */

int64_t itb_set_memory_limit(int64_t bytes)
{
    return ITB_SetMemoryLimit(bytes);
}

int32_t itb_set_gc_percent(int32_t pct)
{
    return (int32_t)ITB_SetGCPercent((int)pct);
}

/* ------------------------------------------------------------------ */
/* Diagnostic registry iteration (CLI tooling)                         */
/* ------------------------------------------------------------------ */

size_t itb_hash_count(void)
{
    int n = ITB_HashCount();
    return n > 0 ? (size_t)n : 0;
}

const char *itb_hash_name(size_t index)
{
    if (index > (size_t)INT_MAX) {
        return NULL;
    }
    size_t need = 0;
    g_hash_name[0] = '\0';
    int rc = ITB_HashName((int)index, g_hash_name, sizeof(g_hash_name), &need);
    if (rc != (int)ITB_STATUS_OK) {
        return NULL;
    }
    return g_hash_name;
}

int itb_hash_width(size_t index)
{
    if (index > (size_t)INT_MAX) {
        return 0;
    }
    int w = ITB_HashWidth((int)index);
    return w > 0 ? w : 0;
}

/* ------------------------------------------------------------------ */
/* Bytes helper                                                        */
/* ------------------------------------------------------------------ */

void itb_bytes_free(uint8_t *bytes)
{
    free(bytes);
}
