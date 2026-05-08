/*
 * errors.c — thread-local last-error capture + size-out-param readers.
 *
 * The wrapper exposes a per-thread last-error pair (status + textual
 * diagnostic) captured at every failing FFI call. Captures happen
 * inside the wrapper (not on the caller's main thread later), so a
 * sibling thread that calls into libitb between the failing call and
 * the diagnostic read does NOT race the textual message — the message
 * has already been copied into thread-local storage.
 *
 * The structural status code returned by every entry point is the
 * authoritative attribution; the textual diagnostic is best-effort.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

/* Thread-local last-error pair. The message buffer is fixed-size so no
 * allocation is needed in the failure path; libitb diagnostics fit
 * comfortably (the longest seen across the test suite is ~120 bytes).
 */
#define ITB_TLS_ERROR_CAP 512
static _Thread_local int  itb_tls_status = ITB_OK;
static _Thread_local char itb_tls_message[ITB_TLS_ERROR_CAP];

itb_status_t itb_last_status(void)
{
    return (itb_status_t) itb_tls_status;
}

const char *itb_last_error(void)
{
    /* Always NUL-terminated by construction; safe to return directly. */
    return itb_tls_message;
}

void itb_internal_reset_error(void)
{
    itb_tls_status = ITB_OK;
    itb_tls_message[0] = '\0';
}

/*
 * Reads ITB_LastError into the thread-local message buffer. The libitb
 * accessor counts a trailing NUL in `written`; this helper writes the
 * visible bytes plus a NUL terminator into the fixed-size TLS buffer
 * (truncating if the diagnostic exceeds the buffer).
 */
static void itb_internal_capture_libitb_error(void)
{
    size_t need = 0;
    int rc = ITB_LastError(NULL, 0, &need);
    if (rc != ITB_OK && rc != ITB_BUFFER_TOO_SMALL) {
        itb_tls_message[0] = '\0';
        return;
    }
    if (need <= 1) {
        itb_tls_message[0] = '\0';
        return;
    }

    /* Cap at TLS buffer size (keep room for trailing NUL). */
    size_t cap = need;
    if (cap > ITB_TLS_ERROR_CAP) {
        cap = ITB_TLS_ERROR_CAP;
    }
    size_t written = 0;
    rc = ITB_LastError(itb_tls_message, cap, &written);
    if (rc != ITB_OK) {
        itb_tls_message[0] = '\0';
        return;
    }
    /* libitb counts the trailing NUL in `written`. Strip it; write our
     * own NUL at the visible-length offset (defensive — libitb already
     * did so, but a future revision that drops the NUL would silently
     * break us). */
    if (written == 0) {
        itb_tls_message[0] = '\0';
        return;
    }
    size_t visible = written - 1;
    if (visible >= ITB_TLS_ERROR_CAP) {
        visible = ITB_TLS_ERROR_CAP - 1;
    }
    itb_tls_message[visible] = '\0';
}

itb_status_t itb_internal_set_error(int rc)
{
    itb_tls_status = rc;
    if (rc == ITB_OK) {
        itb_tls_message[0] = '\0';
        return (itb_status_t) rc;
    }
    itb_internal_capture_libitb_error();
    return (itb_status_t) rc;
}

itb_status_t itb_internal_set_error_msg(int rc, const char *msg)
{
    itb_tls_status = rc;
    if (msg == NULL || msg[0] == '\0') {
        itb_tls_message[0] = '\0';
        return (itb_status_t) rc;
    }
    /* Truncate-copy into TLS buffer with explicit NUL termination.
     * Hand-rolled bounded length to avoid the strnlen() POSIX feature-
     * test macro requirement (`_POSIX_C_SOURCE >= 200809L`). */
    size_t n = 0;
    while (n < ITB_TLS_ERROR_CAP - 1 && msg[n] != '\0') {
        n++;
    }
    memcpy(itb_tls_message, msg, n);
    itb_tls_message[n] = '\0';
    return (itb_status_t) rc;
}

/* ------------------------------------------------------------------ */
/* Size-out-param string reader                                        */
/* ------------------------------------------------------------------ */
/*
 * Probe-then-allocate idiom. *out_len reports VISIBLE length on every
 * code path (matching strlen() semantics — excludes NUL). Caller must
 * allocate at least *out_len + 1 bytes for the second call.
 *
 *   Empty string:    *out_len = 0,     return ITB_OK
 *   Probe non-empty: *out_len = N - 1, return ITB_BUFFER_TOO_SMALL
 *   Read non-empty:  *out_len = N - 1, return ITB_OK, out NUL-terminated
 *
 * NUL-stripped uniformly: libitb's `need` includes the trailing NUL,
 * but *out_len reports VISIBLE length excluding NUL on every code
 * path so callers see consistent strlen()-style semantics.
 */
itb_status_t itb_internal_read_string(itb_internal_str_fn fn, void *ctx,
                                      char *out, size_t cap, size_t *out_len)
{
    if (out_len == NULL) {
        return itb_internal_set_error_msg(ITB_BAD_INPUT, "out_len is NULL");
    }
    *out_len = 0;
    if (out != NULL && cap >= 1) {
        out[0] = '\0';
    }

    /* Probe libitb for required size (libitb counts NUL in `need`). */
    size_t need = 0;
    int rc = fn(NULL, 0, &need, ctx);
    if (rc != ITB_OK && rc != ITB_BUFFER_TOO_SMALL) {
        return itb_internal_set_error(rc);
    }
    if (need <= 1) {
        /* Empty-string short-circuit: visible length is 0. */
        itb_internal_reset_error();
        return ITB_OK;
    }

    /* Non-empty: visible length is need - 1. Caller must provide
     * cap >= need; otherwise report visible length so they can
     * allocate visible + 1 = need bytes. */
    size_t visible = need - 1;
    if (out == NULL || cap < need) {
        *out_len = visible;
        return itb_internal_set_error(ITB_BUFFER_TOO_SMALL);
    }

    /* Sufficient cap: read into caller's buffer. */
    size_t written = 0;
    rc = fn(out, cap, &written, ctx);
    if (rc != ITB_OK) {
        return itb_internal_set_error(rc);
    }
    if (written == 0) {
        out[0] = '\0';
        *out_len = 0;
    } else {
        size_t v = written - 1;
        if (v < cap) {
            out[v] = '\0';
        } else {
            out[cap - 1] = '\0';
        }
        *out_len = v;
    }
    itb_internal_reset_error();
    return ITB_OK;
}

/* Saturating computation of max(131072, n * 5 / 4 + 131072) on size_t.
 * See internal.h docstring. Implementation mirrors the
 * `saturating_expansion` helper in encryptor.c (kept private to that
 * translation unit for the per-encryptor cipher cache); this duplicate
 * is exposed via internal.h for use by every cipher-call dispatcher
 * across cipher.c / streams.c that pre-allocates output capacity. */
size_t itb_internal_buf_cap(size_t payload_len)
{
    size_t mul;
    if (payload_len > (SIZE_MAX / 5)) {
        mul = SIZE_MAX;
    } else {
        mul = (payload_len * 5) / 4;
    }
    size_t add;
    if (mul > SIZE_MAX - 131072) {
        add = SIZE_MAX;
    } else {
        add = mul + 131072;
    }
    return (add < 131072) ? 131072 : add;
}

