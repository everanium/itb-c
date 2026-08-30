/*
 * itb_opts.c — URL-query builder for the opts pass-through string.
 *
 * The builder performs no validation — every key and value is
 * percent-encoded into a query string and passed through to Go
 * verbatim; libitb rejects unknown keys or bad values with a
 * diagnostic surfaced via itb_last_error(). Primitive / MAC / cipher
 * / profile names are opaque strings.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

/* Unreserved URL characters plus ',' (comma-separated list values
 * cross unescaped, matching the fleet convention). */
static int url_safe(unsigned char b)
{
    return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') ||
           (b >= '0' && b <= '9') || b == '-' || b == '.' ||
           b == '_' || b == '~' || b == ',';
}

/* Length of s once percent-encoded. */
static size_t enc_len(const char *s)
{
    size_t n = 0;
    for (const char *p = s; *p != '\0'; p++) {
        n += url_safe((unsigned char)*p) ? 1 : 3;
    }
    return n;
}

/* Percent-encodes s into dst (caller guarantees capacity); returns
 * the number of bytes written (no trailing NUL). */
static size_t enc_write(char *dst, const char *s)
{
    size_t n = 0;
    for (const char *p = s; *p != '\0'; p++) {
        unsigned char b = (unsigned char)*p;
        if (url_safe(b)) {
            dst[n++] = (char)b;
        } else {
            /* 4 = "%XX" + NUL; the NUL is overwritten by the next
             * write or the final terminator. */
            (void)snprintf(dst + n, 4, "%%%02X", (unsigned int)b);
            n += 3;
        }
    }
    return n;
}

itb_opts *itb_opts_new(void)
{
    itb_opts *opts = calloc(1, sizeof(*opts));
    if (opts == NULL) {
        return NULL;
    }
    opts->cap = 64;
    opts->buf = malloc(opts->cap);
    if (opts->buf == NULL) {
        free(opts);
        return NULL;
    }
    opts->buf[0] = '\0';
    opts->len = 0;
    return opts;
}

void itb_opts_free(itb_opts *opts)
{
    if (opts == NULL) {
        return;
    }
    free(opts->buf);
    opts->buf = NULL;
    free(opts);
}

itb_status itb_opts_set(itb_opts *opts, const char *key, const char *value)
{
    if (opts == NULL || opts->buf == NULL || key == NULL || value == NULL) {
        return ITB_STATUS_BAD_INPUT;
    }
    size_t klen = enc_len(key);
    size_t vlen = enc_len(value);
    /* separator '&' (when non-empty) + key + '=' + value + NUL. */
    size_t extra = (opts->len > 0 ? 1 : 0) + klen + 1 + vlen + 1;
    if (extra < klen || opts->len + extra < opts->len) {
        return ITB_STATUS_BAD_INPUT; /* size_t overflow */
    }
    if (opts->len + extra > opts->cap) {
        size_t cap = opts->cap;
        while (cap < opts->len + extra) {
            if (cap > (SIZE_MAX >> 1)) {
                return ITB_STATUS_INTERNAL;
            }
            cap *= 2;
        }
        char *grown = realloc(opts->buf, cap);
        if (grown == NULL) {
            return ITB_STATUS_INTERNAL;
        }
        opts->buf = grown;
        opts->cap = cap;
    }
    size_t n = opts->len;
    if (n > 0) {
        opts->buf[n++] = '&';
    }
    n += enc_write(opts->buf + n, key);
    opts->buf[n++] = '=';
    n += enc_write(opts->buf + n, value);
    opts->buf[n] = '\0';
    opts->len = n;
    return ITB_STATUS_OK;
}

const char *itb_opts_query(const itb_opts *opts)
{
    if (opts == NULL) {
        return NULL;
    }
    return opts->buf != NULL ? opts->buf : "";
}

const char *itb_internal_opts_cstr(const itb_opts *opts)
{
    if (opts == NULL || opts->buf == NULL) {
        return "";
    }
    return opts->buf;
}
