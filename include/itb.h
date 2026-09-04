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
 *
 *     uint8_t *blob = NULL; size_t blob_len = 0;
 *     itb_pipeline_save(sender, &blob, &blob_len);
 *     itb_pipeline_load(blob, blob_len, NULL, 0, NULL, 0, &receiver);
 *     itb_bytes_free(blob);
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
 * buffer; the caller releases it with itb_bytes_free(). Functions
 * with a `char **out` JSON parameter allocate a NUL-terminated string
 * released with itb_string_free(). Handles from itb_pipeline_init /
 * itb_pipeline_load / itb_pipeline_load_f are released with
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
#define ITB_C_VERSION "0.4.1"

/* ------------------------------------------------------------------ */
/* Status codes                                                        */
/* ------------------------------------------------------------------ */
/* Mirror cmd/cshared/internal/capi/errors.go numerically. Codes
 * 11..13 are the Triple blob-record / registry sentinels, 14..17 a
 * reserved block; 19..22 belong to the native Blob surface (not
 * wrapped here but relayed verbatim if libitb ever returns them). */
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
    ITB_STATUS_BLOB_MALFORMED_RECIPE     = 11,
    ITB_STATUS_RECIPE_PRIMITIVE_UNKNOWN  = 12,
    ITB_STATUS_UNKNOWN_PROFILE           = 13,
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
 * consumed by itb_pipeline_init. The builder performs no validation —
 * Go rejects unknown keys and bad values with a diagnostic relayed
 * through itb_last_error(). Profile registration takes a profile JSON
 * object instead (see itb_register). */

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

/* Reconstructs a Pipeline from a blob produced by itb_pipeline_save /
 * itb_pipeline_rekey. Pass perm_master / wrap_master as NULL / 0 to
 * use the blob-embedded masters; to override, supply both (a
 * half-supplied pair is rejected by libitb). The profile shape
 * travels inside the blob — no profile name, no opts. A blob whose
 * record names a primitive absent from the local build fails with
 * ITB_STATUS_RECIPE_PRIMITIVE_UNKNOWN; a record failing the profile
 * field rules with ITB_STATUS_BLOB_MALFORMED_RECIPE. */
itb_status itb_pipeline_load(const uint8_t *blob, size_t blob_len,
                             const uint8_t *perm_master, size_t perm_master_len,
                             const uint8_t *wrap_master, size_t wrap_master_len,
                             itb_pipeline **out);

/* itb_pipeline_load for a blob stored at path; the file is read inside
 * libitb (a missing or unreadable file is ITB_STATUS_BAD_INPUT with
 * the diagnostic in itb_last_error()). */
itb_status itb_pipeline_load_f(const char *path,
                               const uint8_t *perm_master, size_t perm_master_len,
                               const uint8_t *wrap_master, size_t wrap_master_len,
                               itb_pipeline **out);

/* Closes (zeroing key material Go-side) and releases the handle.
 * NULL-safe. Call exactly once per handle. */
void itb_pipeline_free(itb_pipeline *pipe);

/* The current session-bundle blob for the receiver side (the init
 * blob, or the bytes of the latest rekey). *blob_out is allocated
 * (release with itb_bytes_free); on failure it is NULL and
 * *blob_len_out is 0. A closed handle is ITB_STATUS_TRIPLE_CLOSED. */
itb_status itb_pipeline_save(const itb_pipeline *pipe,
                             uint8_t **blob_out, size_t *blob_len_out);

/* Writes the current blob to path inside libitb (mode 0600; the
 * containing directory must exist). File-system failures are
 * ITB_STATUS_BAD_INPUT with the diagnostic in itb_last_error(). */
itb_status itb_pipeline_save_f(const itb_pipeline *pipe, const char *path);

/* Sets the worker cap for every subsequent cipher call. n is clamped
 * by libitb (<= 0 selects auto, > 256 becomes 256); only the handle
 * state is reported. The cap is per-machine and never travels in the
 * blob. */
itb_status itb_pipeline_max_workers(const itb_pipeline *pipe, int n);

/* Rotates the parallax + wrapper masters. The fresh blob is returned
 * through blob_out / blob_len_out when both are non-NULL (release
 * with itb_bytes_free; pass NULL / NULL to discard — the bytes stay
 * available through itb_pipeline_save). Must not run concurrently
 * with cipher calls or open stream sessions on the same Pipeline. */
itb_status itb_pipeline_rekey(itb_pipeline *pipe,
                              const uint8_t *perm, size_t perm_len,
                              const uint8_t *wrap, size_t wrap_len,
                              uint8_t **blob_out, size_t *blob_len_out);

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
/* Profile records                                                     */
/* ------------------------------------------------------------------ */
/* A profile record is the JSON object libitb accepts in itb_register,
 * returns from itb_lookup / itb_inspect, and embeds in every blob:
 * keys name / mode / width / hash / hashes / keybits / mac / tagstub /
 * chunk / wrapper / outer / parallax / palette / segment. Optional
 * keys are omitted when empty / zero. The binding treats the record
 * as an opaque string; every field rule is enforced by libitb. */

/* Decodes the profile record embedded in blob without constructing a
 * Pipeline. *json_out is allocated (release with itb_string_free);
 * NULL on failure. No registry read, no primitive probe. */
itb_status itb_inspect(const uint8_t *blob, size_t blob_len, char **json_out);

/* Registers a user-defined Triple profile under name from a profile
 * JSON record (a non-empty "name" key inside the record must equal
 * name). A duplicate name fails with ITB_STATUS_PROFILE_EXISTS. */
itb_status itb_register(const char *name, const char *profile_json);

/* The profile registered under name — a shipped catalogue entry or a
 * prior itb_register — as its JSON record. *json_out is allocated
 * (release with itb_string_free); NULL on failure. An unregistered
 * name fails with ITB_STATUS_UNKNOWN_PROFILE. */
itb_status itb_lookup(const char *name, char **json_out);

/* The sorted list of every registered profile name as a JSON array of
 * strings. *json_out is allocated (release with itb_string_free);
 * NULL on failure. */
itb_status itb_profiles(char **json_out);

/* ------------------------------------------------------------------ */
/* Runtime + diagnostics                                               */
/* ------------------------------------------------------------------ */

/* The Go-side diagnostic recorded by the most recent failing libitb
 * call. Thread-local snapshot buffer — the returned pointer is owned
 * by the library, valid until the next itb_last_error() call on the
 * same thread; never NULL (empty string when no diagnostic). */
const char *itb_last_error(void);

/* The libitb library version string (e.g. "0.4.1"). Thread-local
 * buffer owned by the library; NULL only if libitb misbehaves. */
const char *itb_version(void);

/* Sets the Go runtime's soft heap limit in bytes; returns the
 * previous limit. A negative value queries without changing. */
int64_t itb_set_memory_limit(int64_t bytes);

/* Sets the Go GC trigger percentage; returns the previous value. A
 * negative value queries without changing. */
int32_t itb_set_gc_percent(int32_t pct);

/* ------------------------------------------------------------------ */
/* Bytes helper                                                        */
/* ------------------------------------------------------------------ */

/* Releases a buffer allocated by the *_message / *_stream_pump /
 * *_stream_one_shot / save / rekey entries. NULL-safe. */
void itb_bytes_free(uint8_t *bytes);

/* Releases a JSON string allocated by itb_inspect / itb_lookup /
 * itb_profiles. NULL-safe. */
void itb_string_free(char *str);

#ifdef __cplusplus
}
#endif

#endif /* ITB_H */
