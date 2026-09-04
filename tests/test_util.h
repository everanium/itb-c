/*
 * test_util.h — minimal assertion + payload helpers shared by the
 * binding's integration tests. No framework dependency: every test is
 * a standalone binary whose main() returns non-zero on failure.
 */

#ifndef ITB_TEST_UTIL_H
#define ITB_TEST_UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "itb.h"

/* Prints file:line + the formatted message and fails the enclosing
 * int-returning function. */
#define TEST_ASSERT(cond, ...)                                        \
    do {                                                              \
        if (!(cond)) {                                                \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);      \
            fprintf(stderr, __VA_ARGS__);                             \
            fprintf(stderr, "\n");                                    \
            return 1;                                                 \
        }                                                             \
    } while (0)

#define TEST_OK(st, what)                                             \
    TEST_ASSERT((st) == ITB_STATUS_OK, "%s: status %d (%s): %s",      \
                (what), (int)(st), itb_status_str(st), itb_last_error())

/* Deterministic non-trivial payload (xorshift fill). Caller frees. */
static inline uint8_t *test_payload(size_t n, uint64_t seed)
{
    uint8_t *buf = malloc(n > 0 ? n : 1);
    if (buf == NULL) {
        return NULL;
    }
    uint64_t x = seed | 1u;
    for (size_t i = 0; i < n; i++) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        buf[i] = (uint8_t)x;
    }
    return buf;
}

/* Saves sender's current blob and loads a receiver from it (the
 * Save → Load handshake every round-trip test starts with). */
static inline itb_status test_load_from(const itb_pipeline *sender,
                                        itb_pipeline **receiver)
{
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    itb_status st = itb_pipeline_save(sender, &blob, &blob_len);
    if (st != ITB_STATUS_OK) {
        return st;
    }
    st = itb_pipeline_load(blob, blob_len, NULL, 0, NULL, 0, receiver);
    itb_bytes_free(blob);
    return st;
}

#endif /* ITB_TEST_UTIL_H */
