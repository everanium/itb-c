/*
 * Shared internals of the ITB C binding.
 *
 * Not installed; consumers include only <itb3.h>. The binding links
 * against libitb3.so at compile time, so the generated libitb3.h
 * prototypes are the FFI surface — no runtime symbol loading.
 */

#ifndef ITB_INTERNAL_H
#define ITB_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "itb3.h"
#include "libitb3.h"

/* Concrete handle layouts behind the public opaque typedefs.
 * Ownership: the structs and every buffer they point at are heap
 * allocations owned by the binding, released by the matching
 * *_free entry. */

struct itb_pipeline {
    uintptr_t handle; /* ITB_Triple_* handle; 0 after free */
};

struct itb_stream {
    uintptr_t handle; /* ITB_Triple_Stream* handle; 0 after free */
};

struct itb_opts {
    char *buf;  /* owned NUL-terminated query string ("" when empty) */
    size_t len; /* strlen(buf)                                       */
    size_t cap; /* allocation size of buf                            */
};

/* Floor capacity for blob / JSON output buffers (Init / Rekey / Save /
 * Inspect / Lookup / Profiles). */
#define ITB_BLOB_CAP ((size_t)(64 * 1024))

/* Feed / drain slice size used by the pump loops. */
#define ITB_PUMP_BUF ((size_t)(1 << 20))

/* Pre-allocation formula for Message outputs:
 * max(131072, payload * 5/4 + 131072). Overflow-guarded. */
size_t itb_internal_out_cap(size_t payload);

/* Normalises a raw libitb3 return code into itb_status (unknown codes
 * collapse to ITB_STATUS_INTERNAL). */
itb_status itb_internal_status(int rc);

/* Renders an opts builder (NULL accepted) as a C string for the FFI
 * call. Never NULL — returns "" for NULL / empty builders. */
const char *itb_internal_opts_cstr(const itb_opts *opts);

/* Zeroes a buffer through a volatile byte pointer so the compiler
 * cannot dead-store-eliminate the wipe before free(). */
static inline void itb_internal_wipe(void *ptr, size_t len)
{
    if (ptr == NULL || len == 0) {
        return;
    }
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

#endif /* ITB_INTERNAL_H */
