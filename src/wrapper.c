/*
 * wrapper.c — format-deniability wrapper layer over libitb's
 * ITB_Wrap* / ITB_Unwrap* / ITB_WrapStream* / ITB_UnwrapStream* /
 * ITB_WrapperKeySize / ITB_WrapperNonceSize FFI exports.
 *
 * Mirrors the Python `itb.wrapper`, Rust `itb::wrapper`, C# `Itb.Wrapper`,
 * and Node.js `itb.wrapper` surfaces against the same libitb ABI.
 * Public API and rationale live in `include/itb.h` under the
 * "Format-deniability wrapper" section header.
 *
 * Allocation contract.
 *   - `itb_wrap` / `itb_unwrap` / `itb_wrapper_generate_key` malloc()
 *     a fresh output buffer; the caller releases via itb_buffer_free().
 *   - `itb_wrap_in_place` / `itb_unwrap_in_place` mutate the caller's
 *     buffer in place; nothing additional is allocated.
 *   - `itb_wrap_stream_writer_new` / `itb_unwrap_stream_reader_new`
 *     malloc() the opaque handle struct and acquire one libitb stream
 *     handle; both are released by the matching _free call.
 *
 * Error handling. Every public entry point captures the failing FFI
 * status + textual diagnostic into the per-thread last-error TLS via
 * itb_internal_set_error / itb_internal_set_error_msg before returning
 * the status code; itb_last_error() reflects the most recent failure
 * on the calling thread.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

/* ------------------------------------------------------------------ */
/* Cipher-name table                                                   */
/* ------------------------------------------------------------------ */
/*
 * Nine interned NUL-terminated short names ("aescmac" / "chacha20" /
 * "siphash24" / "areion256" / "areion512" / "blake2b256" / "blake2b512" /
 * "blake2s" / "blake3") indexed by itb_wrapper_cipher_t. The pointer
 * table is static-storage so the returned pointers stay valid for the
 * life of the process. Out-of-range values map to NULL via the bounds
 * check in itb_wrapper_cipher_name.
 */
static const char *const ITB_WRAPPER_CIPHER_NAMES[] = {
    "aescmac",    /* ITB_WRAPPER_CIPHER_AES_128_CTR */
    "chacha20",   /* ITB_WRAPPER_CIPHER_CHACHA20    */
    "siphash24",  /* ITB_WRAPPER_CIPHER_SIPHASH24   */
    "areion256",  /* ITB_WRAPPER_CIPHER_AREION_256  */
    "areion512",  /* ITB_WRAPPER_CIPHER_AREION_512  */
    "blake2b256", /* ITB_WRAPPER_CIPHER_BLAKE2B_256 */
    "blake2b512", /* ITB_WRAPPER_CIPHER_BLAKE2B_512 */
    "blake2s",    /* ITB_WRAPPER_CIPHER_BLAKE2S     */
    "blake3"      /* ITB_WRAPPER_CIPHER_BLAKE3      */
};

#define ITB_WRAPPER_CIPHER_COUNT \
    ((int) (sizeof(ITB_WRAPPER_CIPHER_NAMES) / sizeof(ITB_WRAPPER_CIPHER_NAMES[0])))

/*
 * Validates a caller-supplied cipher value against the enum range
 * and returns the canonical short name. Sets last-error and returns
 * NULL on out-of-range input so the caller can early-return with the
 * captured diagnostic.
 */
static const char *cipher_name_or_set_error(itb_wrapper_cipher_t cipher)
{
    int idx = (int) cipher;
    if (idx < 0 || idx >= ITB_WRAPPER_CIPHER_COUNT) {
        itb_internal_set_error_msg(
            ITB_BAD_INPUT,
            "wrapper: unknown cipher value (expected one of the nine "
            "supported outer ciphers)");
        return NULL;
    }
    return ITB_WRAPPER_CIPHER_NAMES[idx];
}

const char *itb_wrapper_cipher_name(itb_wrapper_cipher_t cipher)
{
    int idx = (int) cipher;
    if (idx < 0 || idx >= ITB_WRAPPER_CIPHER_COUNT) {
        return NULL;
    }
    return ITB_WRAPPER_CIPHER_NAMES[idx];
}

/* ------------------------------------------------------------------ */
/* Size accessors                                                      */
/* ------------------------------------------------------------------ */

itb_status_t itb_wrapper_key_size(itb_wrapper_cipher_t cipher,
                                  size_t *out_size)
{
    if (out_size == NULL) {
        return itb_internal_set_error_msg(ITB_BAD_INPUT, "out_size is NULL");
    }
    *out_size = 0;
    const char *cn = cipher_name_or_set_error(cipher);
    if (cn == NULL) {
        return ITB_BAD_INPUT;
    }
    size_t n = 0;
    int rc = ITB_WrapperKeySize((char *) cn, &n);
    if (rc != ITB_OK) {
        return itb_internal_set_error(rc);
    }
    *out_size = n;
    itb_internal_reset_error();
    return ITB_OK;
}

itb_status_t itb_wrapper_nonce_size(itb_wrapper_cipher_t cipher,
                                    size_t *out_size)
{
    if (out_size == NULL) {
        return itb_internal_set_error_msg(ITB_BAD_INPUT, "out_size is NULL");
    }
    *out_size = 0;
    const char *cn = cipher_name_or_set_error(cipher);
    if (cn == NULL) {
        return ITB_BAD_INPUT;
    }
    size_t n = 0;
    int rc = ITB_WrapperNonceSize((char *) cn, &n);
    if (rc != ITB_OK) {
        return itb_internal_set_error(rc);
    }
    *out_size = n;
    itb_internal_reset_error();
    return ITB_OK;
}

/* ------------------------------------------------------------------ */
/* CSPRNG key generator                                                */
/* ------------------------------------------------------------------ */
/*
 * Caller-side CSPRNG. The libitb side draws its own per-call nonce
 * from crypto/rand for every Wrap / WrapInPlace / WrapStreamWriter_Init
 * call; this helper is the matching "give me a fresh outer cipher key"
 * convenience that the Python / Rust / etc. bindings expose. Reads
 * /dev/urandom on POSIX hosts.
 *
 * The reason this routes through /dev/urandom rather than Go's
 * crypto/rand via the FFI: the libitb ABI does not expose a generic
 * "fill N random bytes" entry point — it only draws random material
 * internally as part of a bigger operation (nonce generation, fresh
 * seed material, etc.). Reading /dev/urandom directly keeps the
 * semantics the same as every other binding without forcing an
 * extra FFI surface.
 */
static itb_status_t fill_csprng(uint8_t *buf, size_t n)
{
    if (n == 0) {
        return ITB_OK;
    }
    FILE *fp = fopen("/dev/urandom", "rb");
    if (fp == NULL) {
        return itb_internal_set_error_msg(
            ITB_INTERNAL,
            "wrapper: cannot open /dev/urandom for CSPRNG read");
    }
    size_t got = fread(buf, 1, n, fp);
    fclose(fp);
    if (got != n) {
        return itb_internal_set_error_msg(
            ITB_INTERNAL,
            "wrapper: short read from /dev/urandom");
    }
    return ITB_OK;
}

itb_status_t itb_wrapper_generate_key(itb_wrapper_cipher_t cipher,
                                      uint8_t **out_key, size_t *out_key_len)
{
    if (out_key == NULL || out_key_len == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "out_key or out_key_len is NULL");
    }
    *out_key = NULL;
    *out_key_len = 0;

    size_t klen = 0;
    itb_status_t st = itb_wrapper_key_size(cipher, &klen);
    if (st != ITB_OK) {
        return st;
    }
    if (klen == 0) {
        return itb_internal_set_error_msg(
            ITB_INTERNAL, "wrapper: zero key length reported");
    }
    uint8_t *buf = (uint8_t *) malloc(klen);
    if (buf == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }
    itb_status_t rs = fill_csprng(buf, klen);
    if (rs != ITB_OK) {
        free(buf);
        return rs;
    }
    *out_key = buf;
    *out_key_len = klen;
    itb_internal_reset_error();
    return ITB_OK;
}

itb_status_t itb_wrapper_derive_key(itb_wrapper_cipher_t cipher,
                                    const uint8_t *master, size_t master_len,
                                    uint8_t **out_key, size_t *out_key_len)
{
    if (out_key == NULL || out_key_len == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "out_key or out_key_len is NULL");
    }
    *out_key = NULL;
    *out_key_len = 0;

    if (master == NULL && master_len != 0) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "master is NULL with non-zero master_len");
    }
    const char *cn = cipher_name_or_set_error(cipher);
    if (cn == NULL) {
        return ITB_BAD_INPUT;
    }
    size_t klen = 0;
    itb_status_t st = itb_wrapper_key_size(cipher, &klen);
    if (st != ITB_OK) {
        return st;
    }
    if (klen == 0) {
        return itb_internal_set_error_msg(
            ITB_INTERNAL, "wrapper: zero key length reported");
    }
    uint8_t *buf = (uint8_t *) malloc(klen);
    if (buf == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }
    size_t written = 0;
    void *master_arg = (master_len == 0) ? NULL : (void *) master;
    int rc = ITB_WrapperDeriveKey((char *) cn,
                                  master_arg, master_len,
                                  buf, klen, &written);
    if (rc != ITB_OK) {
        free(buf);
        return itb_internal_set_error(rc);
    }
    *out_key = buf;
    *out_key_len = written;
    itb_internal_reset_error();
    return ITB_OK;
}

/* ------------------------------------------------------------------ */
/* Single Message wrap / unwrap                                           */
/* ------------------------------------------------------------------ */

/*
 * libitb's ITB_Wrap rejects (key, blob) when the wrapped key length
 * mismatches the cipher's requirement. The wrapper validates key_len
 * up-front so the resulting last-error message is binding-side and
 * uniform across language bindings; the FFI call still defends in
 * depth against a missed validation here.
 */
static itb_status_t check_key_len(itb_wrapper_cipher_t cipher, size_t key_len)
{
    size_t need = 0;
    itb_status_t st = itb_wrapper_key_size(cipher, &need);
    if (st != ITB_OK) {
        return st;
    }
    if (key_len != need) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT,
            "wrapper: key length mismatch for selected cipher");
    }
    return ITB_OK;
}

itb_status_t itb_wrap(itb_wrapper_cipher_t cipher,
                      const uint8_t *key, size_t key_len,
                      const uint8_t *blob, size_t blob_len,
                      uint8_t **out_wire, size_t *out_wire_len)
{
    if (out_wire == NULL || out_wire_len == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "out_wire or out_wire_len is NULL");
    }
    *out_wire = NULL;
    *out_wire_len = 0;

    if (key == NULL && key_len != 0) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "key is NULL with non-zero key_len");
    }
    if (blob == NULL && blob_len != 0) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "blob is NULL with non-zero blob_len");
    }
    const char *cn = cipher_name_or_set_error(cipher);
    if (cn == NULL) {
        return ITB_BAD_INPUT;
    }
    itb_status_t kst = check_key_len(cipher, key_len);
    if (kst != ITB_OK) {
        return kst;
    }
    size_t nlen = 0;
    itb_status_t nst = itb_wrapper_nonce_size(cipher, &nlen);
    if (nst != ITB_OK) {
        return nst;
    }
    /* Output wire = nonce || keystream-XOR(blob). Allocate exactly
     * that, plus 1 byte to keep malloc(0) off the table for the
     * pathological zero-blob zero-nonce case. */
    size_t cap = nlen + blob_len;
    if (cap == 0) {
        cap = 1;
    }
    uint8_t *buf = (uint8_t *) malloc(cap);
    if (buf == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }
    size_t written = 0;
    /* The FFI side writes nonce || ks-XOR(blob) into the caller buf. */
    void *blob_arg = (blob_len == 0) ? NULL : (void *) blob;
    int rc = ITB_Wrap((char *) cn,
                      (void *) key, key_len,
                      blob_arg, blob_len,
                      buf, cap, &written);
    if (rc != ITB_OK) {
        free(buf);
        return itb_internal_set_error(rc);
    }
    *out_wire = buf;
    *out_wire_len = written;
    itb_internal_reset_error();
    return ITB_OK;
}

itb_status_t itb_unwrap(itb_wrapper_cipher_t cipher,
                        const uint8_t *key, size_t key_len,
                        const uint8_t *wire, size_t wire_len,
                        uint8_t **out_blob, size_t *out_blob_len)
{
    if (out_blob == NULL || out_blob_len == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "out_blob or out_blob_len is NULL");
    }
    *out_blob = NULL;
    *out_blob_len = 0;

    if (key == NULL && key_len != 0) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "key is NULL with non-zero key_len");
    }
    if (wire == NULL && wire_len != 0) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "wire is NULL with non-zero wire_len");
    }
    const char *cn = cipher_name_or_set_error(cipher);
    if (cn == NULL) {
        return ITB_BAD_INPUT;
    }
    itb_status_t kst = check_key_len(cipher, key_len);
    if (kst != ITB_OK) {
        return kst;
    }
    size_t nlen = 0;
    itb_status_t nst = itb_wrapper_nonce_size(cipher, &nlen);
    if (nst != ITB_OK) {
        return nst;
    }
    if (wire_len < nlen) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "wrapper: wire shorter than nonce");
    }
    size_t cap = wire_len - nlen;
    /* malloc(0) is implementation-defined — bump to 1 for the
     * degenerate empty-body case. */
    size_t alloc_cap = (cap == 0) ? 1 : cap;
    uint8_t *buf = (uint8_t *) malloc(alloc_cap);
    if (buf == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }
    size_t written = 0;
    int rc = ITB_Unwrap((char *) cn,
                        (void *) key, key_len,
                        (void *) wire, wire_len,
                        buf, cap, &written);
    if (rc != ITB_OK) {
        free(buf);
        return itb_internal_set_error(rc);
    }
    *out_blob = buf;
    *out_blob_len = written;
    itb_internal_reset_error();
    return ITB_OK;
}

itb_status_t itb_wrap_in_place(itb_wrapper_cipher_t cipher,
                               const uint8_t *key, size_t key_len,
                               uint8_t *blob, size_t blob_len,
                               uint8_t *out_nonce, size_t nonce_cap)
{
    if (key == NULL && key_len != 0) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "key is NULL with non-zero key_len");
    }
    if (blob == NULL && blob_len != 0) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "blob is NULL with non-zero blob_len");
    }
    if (out_nonce == NULL && nonce_cap != 0) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "out_nonce is NULL with non-zero nonce_cap");
    }
    const char *cn = cipher_name_or_set_error(cipher);
    if (cn == NULL) {
        return ITB_BAD_INPUT;
    }
    itb_status_t kst = check_key_len(cipher, key_len);
    if (kst != ITB_OK) {
        return kst;
    }
    size_t nlen = 0;
    itb_status_t nst = itb_wrapper_nonce_size(cipher, &nlen);
    if (nst != ITB_OK) {
        return nst;
    }
    if (nonce_cap < nlen) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "wrapper: out_nonce buffer too small");
    }
    void *blob_arg = (blob_len == 0) ? NULL : (void *) blob;
    int rc = ITB_WrapInPlace((char *) cn,
                             (void *) key, key_len,
                             blob_arg, blob_len,
                             (void *) out_nonce, nonce_cap);
    if (rc != ITB_OK) {
        return itb_internal_set_error(rc);
    }
    itb_internal_reset_error();
    return ITB_OK;
}

itb_status_t itb_unwrap_in_place(itb_wrapper_cipher_t cipher,
                                 const uint8_t *key, size_t key_len,
                                 uint8_t *wire, size_t wire_len)
{
    if (key == NULL && key_len != 0) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "key is NULL with non-zero key_len");
    }
    if (wire == NULL && wire_len != 0) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "wire is NULL with non-zero wire_len");
    }
    const char *cn = cipher_name_or_set_error(cipher);
    if (cn == NULL) {
        return ITB_BAD_INPUT;
    }
    itb_status_t kst = check_key_len(cipher, key_len);
    if (kst != ITB_OK) {
        return kst;
    }
    size_t nlen = 0;
    itb_status_t nst = itb_wrapper_nonce_size(cipher, &nlen);
    if (nst != ITB_OK) {
        return nst;
    }
    if (wire_len < nlen) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "wrapper: wire shorter than nonce");
    }
    int rc = ITB_UnwrapInPlace((char *) cn,
                               (void *) key, key_len,
                               (void *) wire, wire_len);
    if (rc != ITB_OK) {
        return itb_internal_set_error(rc);
    }
    itb_internal_reset_error();
    return ITB_OK;
}

/* ------------------------------------------------------------------ */
/* Streaming wrap-encrypt handle                                       */
/* ------------------------------------------------------------------ */

itb_status_t itb_wrap_stream_writer_new(itb_wrapper_cipher_t cipher,
                                        const uint8_t *key, size_t key_len,
                                        uint8_t *out_nonce, size_t nonce_cap,
                                        itb_wrap_stream_writer_t **out_w)
{
    if (out_w == NULL) {
        return itb_internal_set_error_msg(ITB_BAD_INPUT, "out_w is NULL");
    }
    *out_w = NULL;
    if (key == NULL && key_len != 0) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "key is NULL with non-zero key_len");
    }
    if (out_nonce == NULL && nonce_cap != 0) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "out_nonce is NULL with non-zero nonce_cap");
    }
    const char *cn = cipher_name_or_set_error(cipher);
    if (cn == NULL) {
        return ITB_BAD_INPUT;
    }
    itb_status_t kst = check_key_len(cipher, key_len);
    if (kst != ITB_OK) {
        return kst;
    }
    size_t nlen = 0;
    itb_status_t nst = itb_wrapper_nonce_size(cipher, &nlen);
    if (nst != ITB_OK) {
        return nst;
    }
    if (nonce_cap < nlen) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "wrapper: out_nonce buffer too small");
    }
    itb_wrap_stream_writer_t *w =
        (itb_wrap_stream_writer_t *) calloc(1, sizeof(*w));
    if (w == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }
    uintptr_t handle = 0;
    int rc = ITB_WrapStreamWriter_Init((char *) cn,
                                       (void *) key, key_len,
                                       (void *) out_nonce, nonce_cap,
                                       &handle);
    if (rc != ITB_OK) {
        free(w);
        return itb_internal_set_error(rc);
    }
    w->handle = handle;
    w->closed = 0;
    *out_w = w;
    itb_internal_reset_error();
    return ITB_OK;
}

itb_status_t itb_wrap_stream_writer_update(itb_wrap_stream_writer_t *w,
                                           const uint8_t *src, size_t src_len,
                                           uint8_t *dst, size_t dst_cap)
{
    if (w == NULL || w->closed || w->handle == 0) {
        return itb_internal_set_error_msg(
            ITB_BAD_HANDLE, "wrap_stream_writer is NULL or closed");
    }
    if (src_len == 0) {
        itb_internal_reset_error();
        return ITB_OK;
    }
    if (src == NULL || dst == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "src/dst is NULL with non-zero src_len");
    }
    if (dst_cap < src_len) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "dst_cap shorter than src_len");
    }
    int rc = ITB_WrapStreamWriter_Update(w->handle,
                                         (void *) src, src_len,
                                         (void *) dst, dst_cap);
    if (rc != ITB_OK) {
        return itb_internal_set_error(rc);
    }
    itb_internal_reset_error();
    return ITB_OK;
}

void itb_wrap_stream_writer_free(itb_wrap_stream_writer_t *w)
{
    if (w == NULL) {
        return;
    }
    if (!w->closed && w->handle != 0) {
        /* Best-effort release. The Go-side handle table is idempotent
         * against double-free at the registry layer (returns
         * StatusBadHandle silently); the wrapper still flips the local
         * flag first so a second free is a pure local no-op. */
        (void) ITB_WrapStreamWriter_Free(w->handle);
        w->handle = 0;
        w->closed = 1;
    }
    free(w);
}

/* ------------------------------------------------------------------ */
/* Streaming unwrap-decrypt handle                                     */
/* ------------------------------------------------------------------ */

itb_status_t itb_unwrap_stream_reader_new(itb_wrapper_cipher_t cipher,
                                          const uint8_t *key, size_t key_len,
                                          const uint8_t *wire_nonce,
                                          size_t nonce_len,
                                          itb_unwrap_stream_reader_t **out_r)
{
    if (out_r == NULL) {
        return itb_internal_set_error_msg(ITB_BAD_INPUT, "out_r is NULL");
    }
    *out_r = NULL;
    if (key == NULL && key_len != 0) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "key is NULL with non-zero key_len");
    }
    if (wire_nonce == NULL && nonce_len != 0) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "wire_nonce is NULL with non-zero nonce_len");
    }
    const char *cn = cipher_name_or_set_error(cipher);
    if (cn == NULL) {
        return ITB_BAD_INPUT;
    }
    itb_status_t kst = check_key_len(cipher, key_len);
    if (kst != ITB_OK) {
        return kst;
    }
    size_t nlen = 0;
    itb_status_t nst = itb_wrapper_nonce_size(cipher, &nlen);
    if (nst != ITB_OK) {
        return nst;
    }
    if (nonce_len != nlen) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "wrapper: wire_nonce length mismatch");
    }
    itb_unwrap_stream_reader_t *r =
        (itb_unwrap_stream_reader_t *) calloc(1, sizeof(*r));
    if (r == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }
    uintptr_t handle = 0;
    int rc = ITB_UnwrapStreamReader_Init((char *) cn,
                                         (void *) key, key_len,
                                         (void *) wire_nonce, nonce_len,
                                         &handle);
    if (rc != ITB_OK) {
        free(r);
        return itb_internal_set_error(rc);
    }
    r->handle = handle;
    r->closed = 0;
    *out_r = r;
    itb_internal_reset_error();
    return ITB_OK;
}

itb_status_t itb_unwrap_stream_reader_update(itb_unwrap_stream_reader_t *r,
                                             const uint8_t *src, size_t src_len,
                                             uint8_t *dst, size_t dst_cap)
{
    if (r == NULL || r->closed || r->handle == 0) {
        return itb_internal_set_error_msg(
            ITB_BAD_HANDLE, "unwrap_stream_reader is NULL or closed");
    }
    if (src_len == 0) {
        itb_internal_reset_error();
        return ITB_OK;
    }
    if (src == NULL || dst == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "src/dst is NULL with non-zero src_len");
    }
    if (dst_cap < src_len) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "dst_cap shorter than src_len");
    }
    int rc = ITB_UnwrapStreamReader_Update(r->handle,
                                           (void *) src, src_len,
                                           (void *) dst, dst_cap);
    if (rc != ITB_OK) {
        return itb_internal_set_error(rc);
    }
    itb_internal_reset_error();
    return ITB_OK;
}

void itb_unwrap_stream_reader_free(itb_unwrap_stream_reader_t *r)
{
    if (r == NULL) {
        return;
    }
    if (!r->closed && r->handle != 0) {
        (void) ITB_UnwrapStreamReader_Free(r->handle);
        r->handle = 0;
        r->closed = 1;
    }
    free(r);
}
