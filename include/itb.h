/*
 * itb.h — public C header for the ITB C binding.
 *
 * Thin proxy over the libitb shared library's `ITB_Triple_*` surface
 * (cmd/cshared). The binding links against libitb.so at compile time
 * (`-litb_c -litb`); every hash-name / MAC-name / cipher-name /
 * profile-name is an opaque string passed through to Go for
 * validation — the binding carries no ITB construction logic.
 *
 * Quick start:
 *
 *     #include <itb.h>
 *
 *     itb_pipeline *sender = NULL, *receiver = NULL;
 *     itb_pipeline_init("singlemsg-triple-mac-v1", NULL, &sender);
 *     itb_pipeline_open("singlemsg-triple-mac-v1",
 *                       itb_pipeline_blob(sender),
 *                       itb_pipeline_blob_len(sender),
 *                       NULL, NULL, 0, NULL, 0, &receiver);
 *
 *     uint8_t *wire = NULL; size_t wire_len = 0;
 *     itb_pipeline_encrypt_message(sender, (const uint8_t *)"hi", 2,
 *                                  &wire, &wire_len);
 *
 *     uint8_t *plain = NULL; size_t plain_len = 0;
 *     itb_pipeline_decrypt_message(receiver, wire, wire_len,
 *                                  &plain, &plain_len);
 *
 *     itb_bytes_free(wire);
 *     itb_bytes_free(plain);
 *     itb_pipeline_free(receiver);
 *     itb_pipeline_free(sender);
 *
 * Ownership. Functions with a `**out` byte parameter allocate the
 * buffer; the caller releases it with itb_bytes_free(). Handles from
 * itb_pipeline_init / itb_pipeline_open are released with
 * itb_pipeline_free(); stream sessions with itb_stream_free(). Both
 * free functions are NULL-safe; each handle must be freed exactly
 * once and never used afterwards.
 *
 * Errors. Every fallible entry returns an itb_status. On a non-OK
 * return, out-parameters are left in a safe state (NULL / 0) and
 * itb_last_error() carries the Go-side diagnostic — fetch it
 * immediately after the failing call on the same thread; the
 * underlying store is process-global last-write-wins.
 */

#ifndef ITB_H
#define ITB_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/* Binding version. Tracks the C wrapper; call itb_version() for the
 * underlying libitb library version. */
#define ITB_C_VERSION "0.3.1"

/* ------------------------------------------------------------------ */
/* Status codes                                                        */
/* ------------------------------------------------------------------ */
/* Mirror cmd/cshared/internal/capi/errors.go numerically. Codes
 * 11..17 are a reserved sentinel block; 19..22 belong to the native
 * Blob surface (not wrapped here but relayed verbatim if libitb ever
 * returns them). */
typedef enum itb_status {
    ITB_STATUS_OK                   = 0,
    ITB_STATUS_BAD_HASH             = 1,
    ITB_STATUS_BAD_KEY_BITS         = 2,
    ITB_STATUS_BAD_HANDLE           = 3,
    ITB_STATUS_BAD_INPUT            = 4,
    ITB_STATUS_BUFFER_TOO_SMALL     = 5,
    ITB_STATUS_ENCRYPT_FAILED       = 6,
    ITB_STATUS_DECRYPT_FAILED       = 7,
    ITB_STATUS_SEED_WIDTH_MIX       = 8,
    ITB_STATUS_BAD_MAC              = 9,
    ITB_STATUS_MAC_FAILURE          = 10,
    ITB_STATUS_RESERVED_11          = 11,
    ITB_STATUS_RESERVED_12          = 12,
    ITB_STATUS_RESERVED_13          = 13,
    ITB_STATUS_RESERVED_14          = 14,
    ITB_STATUS_RESERVED_15          = 15,
    ITB_STATUS_RESERVED_16          = 16,
    ITB_STATUS_RESERVED_17          = 17,
    ITB_STATUS_BLOB_MODE_MISMATCH   = 19,
    ITB_STATUS_BLOB_MALFORMED       = 20,
    ITB_STATUS_BLOB_VERSION_TOO_NEW = 21,
    ITB_STATUS_BLOB_TOO_MANY_OPTS   = 22,
    ITB_STATUS_STREAM_TRUNCATED     = 23,
    ITB_STATUS_STREAM_AFTER_FINAL   = 24,
    ITB_STATUS_TRIPLE_CLOSED        = 25,
    ITB_STATUS_PROFILE_EXISTS       = 26,
    ITB_STATUS_INTERNAL             = 99
} itb_status;

/* Short static label for a status code. Never NULL; the pointer is a
 * string literal — do not free. */
const char *itb_status_str(itb_status status);

/* ------------------------------------------------------------------ */
/* Opaque handle types                                                 */
/* ------------------------------------------------------------------ */

typedef struct itb_pipeline itb_pipeline; /* Triple Pipeline session   */
typedef struct itb_stream itb_stream;     /* incremental stream session */
typedef struct itb_opts itb_opts;         /* URL-query opts builder     */

/* ------------------------------------------------------------------ */
/* Opts builder                                                        */
/* ------------------------------------------------------------------ */
/* Accumulates key=value pairs into the URL-query-encoded opts string
 * consumed by init / open / register-profile. The builder performs no
 * validation — Go rejects unknown keys and bad values with a
 * diagnostic relayed through itb_last_error(). */

/* Allocates an empty builder; NULL on allocation failure. Release
 * with itb_opts_free(). */
itb_opts *itb_opts_new(void);

/* Releases a builder. NULL-safe. */
void itb_opts_free(itb_opts *opts);

/* Appends one key=value pair (both percent-encoded as needed). */
itb_status itb_opts_set(itb_opts *opts, const char *key, const char *value);

/* The built query string. Owned by the builder — do not free; valid
 * until the next itb_opts_set / itb_opts_free on the same builder.
 * Returns "" for an empty builder, NULL only for a NULL builder. */
const char *itb_opts_query(const itb_opts *opts);

/* ------------------------------------------------------------------ */
/* Pipeline                                                            */
/* ------------------------------------------------------------------ */

/* Constructs a fresh Pipeline against the named profile. opts may be
 * NULL for pure profile defaults. On success *out receives a handle
 * released with itb_pipeline_free(); on failure *out is NULL. */
itb_status itb_pipeline_init(const char *profile, const itb_opts *opts,
                             itb_pipeline **out);

/* Reconstructs a Pipeline from a blob produced by a sender's init /
 * rekey. Pass perm_master / wrap_master as NULL / 0 to use the
 * blob-embedded masters; to override, both masters must be supplied
 * non-empty (a half-supplied pair is rejected). */
itb_status itb_pipeline_open(const char *profile,
                             const uint8_t *blob, size_t blob_len,
                             const itb_opts *opts,
                             const uint8_t *perm_master, size_t perm_master_len,
                             const uint8_t *wrap_master, size_t wrap_master_len,
                             itb_pipeline **out);

/* Closes (zeroing key material Go-side) and releases the handle.
 * NULL-safe. Call exactly once per handle. */
void itb_pipeline_free(itb_pipeline *pipe);

/* The exported session-bundle blob for the receiver side. The pointer
 * is owned by the Pipeline and stays valid until the next rekey or
 * free. NULL / 0 for a NULL pipe. */
const uint8_t *itb_pipeline_blob(const itb_pipeline *pipe);
size_t itb_pipeline_blob_len(const itb_pipeline *pipe);

/* Rotates the parallax + wrapper masters and refreshes the blob. Must
 * not run concurrently with cipher calls or open stream sessions on
 * the same Pipeline. */
itb_status itb_pipeline_rekey(itb_pipeline *pipe,
                              const uint8_t *perm, size_t perm_len,
                              const uint8_t *wrap, size_t wrap_len);

/* Single Message encrypt: one call, one self-contained wire.
 * *wire_out is allocated (release with itb_bytes_free); on failure it
 * is NULL and *wire_len_out is 0. */
itb_status itb_pipeline_encrypt_message(const itb_pipeline *pipe,
                                        const uint8_t *plain, size_t plain_len,
                                        uint8_t **wire_out, size_t *wire_len_out);

/* Receive-side counterpart of itb_pipeline_encrypt_message. */
itb_status itb_pipeline_decrypt_message(const itb_pipeline *pipe,
                                        const uint8_t *wire, size_t wire_len,
                                        uint8_t **plain_out, size_t *plain_len_out);

/* Pumps the whole plaintext through an incremental encrypt session
 * (begin → write slices → end → drain → free) and returns the
 * concatenated wire in one allocated buffer. Bounded feed / drain
 * slices internally; the output buffer grows to the full wire size. */
itb_status itb_pipeline_encrypt_stream_pump(const itb_pipeline *pipe,
                                            const uint8_t *plain, size_t plain_len,
                                            uint8_t **wire_out, size_t *wire_len_out);

/* Receive-side counterpart of itb_pipeline_encrypt_stream_pump. */
itb_status itb_pipeline_decrypt_stream_pump(const itb_pipeline *pipe,
                                            const uint8_t *wire, size_t wire_len,
                                            uint8_t **plain_out, size_t *plain_len_out);

/* One-shot stream encrypt for callers holding the whole plaintext in
 * memory: a single FFI round trip through the Pipeline's stream
 * chain. For bounded-memory streaming use
 * itb_pipeline_encrypt_stream_pump or the incremental
 * itb_pipeline_encrypt_stream_begin session. *wire_out is allocated
 * (release with itb_bytes_free); on failure it is NULL and
 * *wire_len_out is 0. */
itb_status itb_pipeline_encrypt_stream_one_shot(const itb_pipeline *pipe,
                                                const uint8_t *plain, size_t plain_len,
                                                uint8_t **wire_out, size_t *wire_len_out);

/* Receive-side counterpart of itb_pipeline_encrypt_stream_one_shot. */
itb_status itb_pipeline_decrypt_stream_one_shot(const itb_pipeline *pipe,
                                                const uint8_t *wire, size_t wire_len,
                                                uint8_t **plain_out, size_t *plain_len_out);

/* Opens an incremental encrypt session (plaintext in, wire out). The
 * session must be released with itb_stream_free() and must not
 * outlive its Pipeline. */
itb_status itb_pipeline_encrypt_stream_begin(const itb_pipeline *pipe,
                                             itb_stream **out);

/* Receive-side counterpart (wire in, plaintext out). */
itb_status itb_pipeline_decrypt_stream_begin(const itb_pipeline *pipe,
                                             itb_stream **out);

/* ------------------------------------------------------------------ */
/* Stream session                                                      */
/* ------------------------------------------------------------------ */

/* Feeds src[0..src_len) into the session. Blocks until the cipher
 * chain accepts the bytes; errors are sticky. src_len == 0 is a
 * no-op. */
itb_status itb_stream_write(itb_stream *stream,
                            const uint8_t *src, size_t src_len);

/* Signals end-of-input. Idempotent; a write after end fails with
 * ITB_STATUS_BAD_INPUT. */
itb_status itb_stream_end(itb_stream *stream);

/* Drains up to dst_cap produced bytes into dst. *n_read receives the
 * byte count (0 when nothing is currently available); *finished
 * receives 1 once the session has ended AND the output is fully
 * drained. Partial drains are the normal mode. After end, an
 * empty-spool read blocks until the terminal bytes arrive or the
 * session errors. */
itb_status itb_stream_read(itb_stream *stream,
                           uint8_t *dst, size_t dst_cap,
                           size_t *n_read, int *finished);

/* Cancels (if still running) and releases the session. Safe from any
 * state — mid-flight, mid-error, or after a clean drain. NULL-safe.
 * Call exactly once per session. */
void itb_stream_free(itb_stream *stream);

/* ------------------------------------------------------------------ */
/* Profile registration                                                */
/* ------------------------------------------------------------------ */

/* Registers a user-defined Triple profile under name; the opts follow
 * the register-profile grammar validated by Go. A duplicate name
 * fails with ITB_STATUS_PROFILE_EXISTS. */
itb_status itb_register_profile(const char *name, const itb_opts *opts);

/* ------------------------------------------------------------------ */
/* Runtime + diagnostics                                               */
/* ------------------------------------------------------------------ */

/* The Go-side diagnostic recorded by the most recent failing libitb
 * call. Thread-local snapshot buffer — the returned pointer is owned
 * by the library, valid until the next itb_last_error() call on the
 * same thread; never NULL (empty string when no diagnostic). */
const char *itb_last_error(void);

/* The libitb library version string (e.g. "0.3.1"). Thread-local
 * buffer owned by the library; NULL only if libitb misbehaves. */
const char *itb_version(void);

/* Sets the Go runtime's soft heap limit in bytes; returns the
 * previous limit. A negative value queries without changing. */
int64_t itb_set_memory_limit(int64_t bytes);

/* Sets the Go GC trigger percentage; returns the previous value. A
 * negative value queries without changing. */
int32_t itb_set_gc_percent(int32_t pct);

/* Diagnostic registry iteration for CLI tooling (the binding library
 * itself performs no primitive-name validation or enumeration). */
size_t itb_hash_count(void);

/* Canonical name of the index-th shipped hash primitive. Thread-local
 * buffer owned by the library, valid until the next itb_hash_name()
 * call on the same thread; NULL when index is out of range. */
const char *itb_hash_name(size_t index);

/* Native state width in bits of the index-th shipped hash primitive;
 * 0 when index is out of range. */
int itb_hash_width(size_t index);

/* ------------------------------------------------------------------ */
/* Bytes helper                                                        */
/* ------------------------------------------------------------------ */

/* Releases a buffer allocated by the *_message / *_stream_pump /
 * *_stream_one_shot entries. NULL-safe. */
void itb_bytes_free(uint8_t *bytes);

#ifdef __cplusplus
}
#endif

#endif /* ITB_H */
