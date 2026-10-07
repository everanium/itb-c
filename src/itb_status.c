/*
 * Status-code narrowing, last-error fetch, and runtime knobs.
 */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

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
/* String getters over the (out, cap, *out_len) libitb3 contract        */
/* ------------------------------------------------------------------ */

/* Thread-local snapshot buffers. The libitb3 diagnostics are short
 * sentences; 2 KiB holds every message the Go side emits without
 * touching the allocator. */
#define ITB_ERRBUF_CAP ((size_t)2048)
static _Thread_local char g_last_error[ITB_ERRBUF_CAP];
static _Thread_local char g_version[64];
static _Thread_local char g_drbg_auto_tier[64];

/* Overflow storage for a diagnostic wider than the inline buffer.
 * Released at the head of the next fetch on the same thread, which is
 * exactly the lifetime <itb3.h> promises for the returned pointer, so
 * at most one such allocation is live per thread.
 *
 * The slot is a pthread key rather than a _Thread_local pointer
 * because a thread that fetches a wide diagnostic and then exits never
 * reaches its own next fetch: the pointer dies with the thread and the
 * block outlives it. A key carries a destructor, so the release
 * happens on whichever path the thread leaves by. Threads that come
 * and go are the ordinary shape of a caller, not an unusual one. */
static pthread_key_t g_wide_key;
static pthread_once_t g_wide_key_once = PTHREAD_ONCE_INIT;

static void itb_wide_key_make(void)
{
    (void)pthread_key_create(&g_wide_key, free);
}

const char *itb_last_error(void)
{
    size_t need = 0;

    (void)pthread_once(&g_wide_key_once, itb_wide_key_make);
    free(pthread_getspecific(g_wide_key));
    (void)pthread_setspecific(g_wide_key, NULL);

    g_last_error[0] = '\0';
    int rc = ITB_LastError(g_last_error, sizeof(g_last_error), &need);
    if (rc == (int)ITB_STATUS_OK) {
        return g_last_error;
    }
    /* The diagnostic is the only text an error carries, so losing it
     * to a short buffer would leave the caller holding a bare number.
     * The library reports the size it needed, so ask again at that
     * size rather than giving up. */
    if (rc == (int)ITB_STATUS_BUFFER_TOO_SMALL && need > 1) {
        char *wide = malloc(need);
        if (wide != NULL) {
            size_t wrote = 0;
            wide[0] = '\0';
            if (ITB_LastError(wide, need, &wrote) == (int)ITB_STATUS_OK &&
                pthread_setspecific(g_wide_key, wide) == 0) {
                return wide;
            }
            free(wide);
        }
    }
    g_last_error[0] = '\0';
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

const char *itb_drbg_auto_tier(void)
{
    size_t need = 0;
    g_drbg_auto_tier[0] = '\0';
    int rc = ITB_DRBGAutoTier(g_drbg_auto_tier, sizeof(g_drbg_auto_tier), &need);
    if (rc != (int)ITB_STATUS_OK) {
        return NULL;
    }
    return g_drbg_auto_tier;
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

int32_t itb_set_gomaxprocs(int32_t n)
{
    return (int32_t)ITB_SetGOMAXPROCS((int)n);
}

itb_status itb_write_heap_profile(const char *path)
{
    return itb_internal_status(ITB_WriteHeapProfile((char *)path));
}

size_t itb_pool_stats_len(void)
{
    int n = ITB_PoolStatsLen();
    return n > 0 ? (size_t)n : 0;
}

itb_status itb_pool_stats(int64_t *out, size_t cap, size_t *len_out)
{
    if (len_out == NULL || (out == NULL && cap > 0)) {
        return ITB_STATUS_BAD_INPUT;
    }
    *len_out = 0;
    return itb_internal_status(ITB_PoolStats(out, cap, len_out));
}

/* ------------------------------------------------------------------ */
/* Bytes helper                                                        */
/* ------------------------------------------------------------------ */

void itb_bytes_free(uint8_t *bytes)
{
    free(bytes);
}

void itb_string_free(char *str)
{
    free(str);
}
