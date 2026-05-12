/*
 * itb.h — public C header for the ITB cipher library.
 *
 * Wraps the C ABI exported by `cmd/cshared` (libitb.so / .dll / .dylib)
 * with opaque-handle types, a structured status enum, and a thread-local
 * last-error accessor. The wrapper is link-time: consumer applications
 * link `-litb_c -litb` and the dynamic loader resolves the underlying
 * `ITB_*` exports against `libitb.so` at process start.
 *
 * Quick start:
 *
 *     #include <itb.h>
 *
 *     itb_seed_t *n = NULL, *d = NULL, *s = NULL;
 *     itb_seed_new("blake3", 1024, &n);
 *     itb_seed_new("blake3", 1024, &d);
 *     itb_seed_new("blake3", 1024, &s);
 *
 *     uint8_t *ct = NULL; size_t ct_len = 0;
 *     itb_encrypt(n, d, s, "hello world", 11, &ct, &ct_len);
 *
 *     uint8_t *pt = NULL; size_t pt_len = 0;
 *     itb_decrypt(n, d, s, ct, ct_len, &pt, &pt_len);
 *
 *     itb_buffer_free(ct);
 *     itb_buffer_free(pt);
 *     itb_seed_free(n);
 *     itb_seed_free(d);
 *     itb_seed_free(s);
 *
 * Hash names match the canonical FFI registry (see hashes/registry.go):
 * "areion256", "areion512", "siphash24", "aescmac", "blake2b256",
 * "blake2b512", "blake2s", "blake3", "chacha20".
 *
 * MAC names: "kmac256", "hmac-sha256", "hmac-blake3".
 *
 * Threading. The low-level free functions in this header
 * (itb_encrypt / itb_decrypt / itb_encrypt_auth / itb_decrypt_auth and
 * the Triple-Ouroboros variants) are thread-safe: each call allocates
 * its own output buffer and the underlying libitb worker pool dispatches
 * encrypts independently. Process-wide setters (itb_set_bit_soup,
 * itb_set_lock_soup, itb_set_max_workers, itb_set_nonce_bits,
 * itb_set_barrier_fill) are atomic stores — each setter call atomically
 * updates a single counter and is safe to invoke from any thread in
 * isolation. The caveat is logical, not atomic: changing a knob WHILE
 * an encrypt / decrypt call is in flight can corrupt that operation —
 * the cipher snapshots the configuration at call entry and a
 * mid-flight change breaks the running invariants. Treat the global
 * knobs as set-once-at-startup; rare runtime updates need external
 * sequencing against active cipher calls. itb_seed_attach_lock_seed
 * mutates seed state (not a single atomic counter) — it is NOT
 * thread-safe and must be called outside any in-flight cipher
 * operation on the same noise seed.
 *
 * The textual diagnostic surfaced by itb_last_error() is captured into
 * thread-local storage on every failing call, so concurrent threads do
 * not race on it. The structural status code returned by every entry
 * point is unaffected by thread interleaving.
 */

#ifndef ITB_H
#define ITB_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/* Binding version. Tracks the C wrapper, not the underlying libitb.so;
 * call itb_version() for the libitb library version. */
#define ITB_C_VERSION "0.1.0"

/* ------------------------------------------------------------------ */
/* Status codes                                                        */
/* ------------------------------------------------------------------ */
/*
 * Mirror the constants in cmd/cshared/internal/capi/errors.go bit-
 * identically. Codes 0..10 cover the low-level Seed / Encrypt / Decrypt
 * / MAC surface. Codes 11..18 are reserved for the Easy Mode encryptor.
 * Codes 19..22 are reserved for the native Blob surface. Code 99 is a
 * generic "internal" sentinel for paths the caller cannot recover from
 * at the binding layer.
 *
 * Cross-binding alignment: Rust src/ffi.rs STATUS_*, C# Itb.Native.Status,
 * Node.js src/status.ts, Python itb._status, Ada Itb.Status, D itb.status
 * all carry these same names with the same numeric values.
 */
typedef enum itb_status {
    ITB_OK                              =  0,
    ITB_BAD_HASH                        =  1,
    ITB_BAD_KEY_BITS                    =  2,
    ITB_BAD_HANDLE                      =  3,
    ITB_BAD_INPUT                       =  4,
    ITB_BUFFER_TOO_SMALL                =  5,
    ITB_ENCRYPT_FAILED                  =  6,
    ITB_DECRYPT_FAILED                  =  7,
    ITB_SEED_WIDTH_MIX                  =  8,
    ITB_BAD_MAC                         =  9,
    ITB_MAC_FAILURE                     = 10,

    ITB_EASY_CLOSED                     = 11,
    ITB_EASY_MALFORMED                  = 12,
    ITB_EASY_VERSION_TOO_NEW            = 13,
    ITB_EASY_UNKNOWN_PRIMITIVE          = 14,
    ITB_EASY_UNKNOWN_MAC                = 15,
    ITB_EASY_BAD_KEY_BITS               = 16,
    ITB_EASY_MISMATCH                   = 17,
    ITB_EASY_LOCKSEED_AFTER_ENCRYPT     = 18,

    ITB_BLOB_MODE_MISMATCH              = 19,
    ITB_BLOB_MALFORMED                  = 20,
    ITB_BLOB_VERSION_TOO_NEW            = 21,
    ITB_BLOB_TOO_MANY_OPTS              = 22,

    /* Binding-side Streaming AEAD diagnostics. The libitb ABI itself
     * stops at code 22 — these two codes are introduced by the C
     * binding's stream loop to attribute the two end-of-stream failure
     * modes the per-chunk ABI cannot signal directly:
     *   ITB_STREAM_TRUNCATED   : input ran out without observing a
     *                            terminating chunk (final_flag == 1).
     *   ITB_STREAM_AFTER_FINAL : extra chunk bytes followed the
     *                            terminating chunk on the wire.
     * The numeric values are private to the C binding and do not
     * appear in the libitb header. */
    ITB_STREAM_TRUNCATED                = 23,
    ITB_STREAM_AFTER_FINAL              = 24,

    ITB_INTERNAL                        = 99
} itb_status_t;

/* ------------------------------------------------------------------ */
/* Opaque handle types                                                 */
/* ------------------------------------------------------------------ */
/*
 * Forward-declared opaque structs. Concrete layout lives in
 * src/internal.h and is intentionally hidden from consumers — reaching
 * into the struct fields is not part of the API contract and would
 * silently break across binding revisions.
 */
typedef struct itb_seed itb_seed_t;
typedef struct itb_mac  itb_mac_t;

/* ------------------------------------------------------------------ */
/* Last-error accessors (per-thread)                                   */
/* ------------------------------------------------------------------ */

/*
 * Returns the most recent libitb status code captured on the calling
 * thread. Returns ITB_OK if the calling thread has not yet seen a
 * non-OK return value. The structural code is the only piece of error
 * information reliably attributable to a specific failing call.
 */
itb_status_t itb_last_status(void);

/*
 * Returns the textual diagnostic associated with the most recent non-OK
 * status on the calling thread, or the empty string if none is on
 * record. The pointer is owned by thread-local storage and remains
 * valid until the next libitb call on the same thread; copy the bytes
 * out if longer-lived storage is needed.
 *
 * Never returns NULL; on first-call-with-no-error returns "".
 */
const char *itb_last_error(void);

/* ------------------------------------------------------------------ */
/* Library globals                                                     */
/* ------------------------------------------------------------------ */

/*
 * Writes the libitb library version string into `out` (NUL-terminated).
 * Two-call probe: pass `out=NULL, cap=0` first to discover the required
 * size in `*out_len` (returns ITB_BUFFER_TOO_SMALL); then allocate a
 * buffer of that size and call again. The trailing NUL byte that
 * libitb writes is stripped by this wrapper — *out_len is the visible
 * string length.
 */
itb_status_t itb_version(char *out, size_t cap, size_t *out_len);

/* Returns the maximum supported ITB key width in bits (currently 2048). */
int itb_max_key_bits(void);

/* Returns the number of native-channel slots (typically 7). */
int itb_channels(void);

/*
 * Returns the current ciphertext-chunk header size in bytes
 * (nonce + width(2) + height(2)). Tracks itb_set_nonce_bits().
 */
int itb_header_size(void);

/*
 * Inspects a chunk header and returns the total chunk length on the
 * wire via *out_chunk_len. Returns ITB_BAD_INPUT on too-short buffer,
 * zero dimensions, or arithmetic overflow.
 */
itb_status_t itb_parse_chunk_len(const void *header, size_t header_len,
                                 size_t *out_chunk_len);

/* Hash registry --------------------------------------------------------- */

/* Number of hash primitives in the canonical FFI registry. */
int itb_hash_count(void);

/*
 * Writes the canonical name of hash `i` into `out` (NUL-stripped).
 * Two-call probe: see itb_version(). Returns ITB_BAD_INPUT for `i` out
 * of range.
 */
itb_status_t itb_hash_name(int i, char *out, size_t cap, size_t *out_len);

/* Returns the native hash width of primitive `i` in bits (128/256/512), or 0 on error. */
int itb_hash_width(int i);

/* MAC registry ---------------------------------------------------------- */

/* Number of MAC primitives in the canonical FFI registry. */
int itb_mac_count(void);

/* Writes canonical MAC name of slot `i` into `out` (NUL-stripped). */
itb_status_t itb_mac_name(int i, char *out, size_t cap, size_t *out_len);

/* Returns the keying material width of MAC `i` in bytes, or 0 on error. */
int itb_mac_key_size(int i);

/* Returns the tag size of MAC `i` in bytes, or 0 on error. */
int itb_mac_tag_size(int i);

/* Returns the minimum acceptable key length of MAC `i` in bytes, or 0 on error. */
int itb_mac_min_key_bytes(int i);

/* Process-wide knobs --------------------------------------------------- */

/*
 * The set_* / get_* knobs below are process-global libitb state.
 * Setter calls are atomic — each one atomically updates a single
 * counter and is safe to invoke from any thread in isolation. The
 * caveat is logical rather than atomic: changing a knob WHILE a
 * cipher call is in flight can corrupt that operation (the cipher
 * snapshots the configuration at call entry and a mid-flight change
 * breaks the running invariants). Treat the knobs as set-once-at-
 * startup, or sequence rare runtime updates externally against
 * active cipher calls.
 */
itb_status_t itb_set_bit_soup(int mode);
int          itb_get_bit_soup(void);
itb_status_t itb_set_lock_soup(int mode);
int          itb_get_lock_soup(void);
itb_status_t itb_set_max_workers(int n);
int          itb_get_max_workers(void);

/* Accepts 128, 256, or 512. Other values return ITB_BAD_INPUT. */
itb_status_t itb_set_nonce_bits(int n);
int          itb_get_nonce_bits(void);

/* Accepts 1, 2, 4, 8, 16, or 32. Other values return ITB_BAD_INPUT. */
itb_status_t itb_set_barrier_fill(int n);
int          itb_get_barrier_fill(void);

/**
 * Configures the Go runtime's heap-size soft limit (bytes). Pass -1
 * (or any negative value) to query the current limit without changing
 * it; the previous limit is returned. Setter calls override any
 * ITB_GOMEMLIMIT env var set at libitb load time.
 */
int64_t itb_set_memory_limit(int64_t limit);

/**
 * Configures the Go runtime's GC trigger percentage. The default is
 * 100 (GC fires at +100% heap growth); lower values trigger GC more
 * aggressively. Pass -1 (or any negative value) to query the current
 * value without changing it; the previous value is returned. Setter
 * calls override any ITB_GOGC env var set at libitb load time.
 */
int itb_set_gc_percent(int pct);

/* ------------------------------------------------------------------ */
/* Seed                                                                */
/* ------------------------------------------------------------------ */

/*
 * Constructs a fresh seed with CSPRNG-generated keying material.
 *
 * `hash_name` is a canonical hash name from itb_hash_name() (e.g.
 * "blake3", "areion256"). `key_bits` is the ITB key width in bits —
 * 512, 1024, or 2048 (multiple of 64).
 *
 * On success, *out is populated with a freshly-constructed seed handle
 * which the caller must free with itb_seed_free(). On failure, *out is
 * set to NULL and a non-OK status is returned; itb_last_error() carries
 * the textual diagnostic.
 */
itb_status_t itb_seed_new(const char *hash_name, int key_bits,
                          itb_seed_t **out);

/*
 * Builds a seed deterministically from caller-supplied uint64
 * components and an optional fixed hash key.
 *
 * `components_len` is in 8..=32 (multiple of 8). `hash_key_len`, when
 * non-zero, must match the primitive's native fixed-key size: 16 for
 * "aescmac"; 32 for "areion256" / "blake2{s,b256}" / "blake3" /
 * "chacha20"; 64 for "areion512" / "blake2b512". Pass `hash_key=NULL,
 * hash_key_len=0` for "siphash24" (no internal fixed key) or to request
 * a CSPRNG-generated key (only the components fix).
 */
itb_status_t itb_seed_from_components(const char *hash_name,
                                      const uint64_t *components,
                                      size_t components_len,
                                      const uint8_t *hash_key,
                                      size_t hash_key_len,
                                      itb_seed_t **out);

/* Releases the seed handle. NULL is accepted (no-op). Idempotent. */
void itb_seed_free(itb_seed_t *s);

/* Returns the seed's native hash width in bits (128 / 256 / 512). */
itb_status_t itb_seed_width(const itb_seed_t *s, int *out_width);

/*
 * Writes the seed's canonical hash name into `out` (NUL-stripped).
 * Two-call probe pattern.
 */
itb_status_t itb_seed_hash_name(const itb_seed_t *s,
                                char *out, size_t cap, size_t *out_len);

/*
 * Writes the seed's fixed-key bytes into `out`. Two-call probe: pass
 * `out=NULL, cap=0` first to discover the required size in *out_len,
 * then allocate. SipHash-2-4 has no internal fixed key — *out_len
 * comes back as 0.
 */
itb_status_t itb_seed_hash_key(const itb_seed_t *s,
                               uint8_t *out, size_t cap, size_t *out_len);

/*
 * Writes the seed's underlying uint64 components into `out`. Two-call
 * probe (count-of-uint64 in *out_count, not byte count).
 */
itb_status_t itb_seed_components(const itb_seed_t *s,
                                 uint64_t *out, size_t cap_count,
                                 size_t *out_count);

/*
 * Wires a dedicated lockSeed onto this noise seed.
 *
 * The dedicated lockSeed has no observable effect on the wire output
 * unless the bit-permutation overlay is engaged via itb_set_bit_soup(1)
 * or itb_set_lock_soup(1) before the first encrypt / decrypt call.
 * Both seeds must share the same native hash width.
 *
 * The lockSeed remains owned by the caller — attach only records a
 * pointer on the noise seed, so keep the lockSeed handle alive for the
 * lifetime of the noise seed (do not itb_seed_free() the lockSeed
 * before the noise seed is finished).
 *
 * Misuse paths surface as ITB_BAD_INPUT (self-attach,
 * post-encrypt switching) or ITB_SEED_WIDTH_MIX (width mismatch).
 */
itb_status_t itb_seed_attach_lock_seed(itb_seed_t *noise,
                                       const itb_seed_t *lock_seed);

/* ------------------------------------------------------------------ */
/* MAC                                                                 */
/* ------------------------------------------------------------------ */

/*
 * Constructs a fresh MAC handle.
 *
 * `mac_name` is a canonical name from itb_mac_name() ("kmac256",
 * "hmac-sha256", "hmac-blake3"). `key_len` must meet the primitive's
 * itb_mac_min_key_bytes() requirement.
 */
itb_status_t itb_mac_new(const char *mac_name,
                         const uint8_t *key, size_t key_len,
                         itb_mac_t **out);

/* Releases the MAC handle. NULL is accepted (no-op). Idempotent. */
void itb_mac_free(itb_mac_t *m);

/* ------------------------------------------------------------------ */
/* Cipher (Single Ouroboros — three seeds)                             */
/* ------------------------------------------------------------------ */
/*
 * The cipher entry points allocate the output buffer internally with
 * malloc(); the caller frees it with itb_buffer_free() (a thin wrapper
 * around free() so applications that override malloc/free see a single
 * cross-binding-friendly entry point).
 *
 * Empty plaintext / ciphertext is rejected by libitb itself with
 * ITB_ENCRYPT_FAILED (the Go-side `Encrypt128` / `Decrypt128` family
 * returns "itb: empty data" before any work). The binding propagates
 * the rejection verbatim — pass at least one byte.
 *
 * On error, *out_buf is set to NULL, *out_len to 0, and the structural
 * status is returned; itb_last_error() carries the textual diagnostic.
 */

/* Encrypts `plaintext` under the (noise, data, start) seed trio. */
itb_status_t itb_encrypt(const itb_seed_t *noise,
                         const itb_seed_t *data,
                         const itb_seed_t *start,
                         const void *plaintext, size_t plaintext_len,
                         uint8_t **out_buf, size_t *out_len);

/* Decrypts ciphertext produced by itb_encrypt() under the same trio. */
itb_status_t itb_decrypt(const itb_seed_t *noise,
                         const itb_seed_t *data,
                         const itb_seed_t *start,
                         const void *ciphertext, size_t ciphertext_len,
                         uint8_t **out_buf, size_t *out_len);

/* Authenticated single-Ouroboros encrypt with MAC-Inside-Encrypt. */
itb_status_t itb_encrypt_auth(const itb_seed_t *noise,
                              const itb_seed_t *data,
                              const itb_seed_t *start,
                              const itb_mac_t *mac,
                              const void *plaintext, size_t plaintext_len,
                              uint8_t **out_buf, size_t *out_len);

/* Authenticated single-Ouroboros decrypt. Returns ITB_MAC_FAILURE on
 * tampered ciphertext or wrong MAC key. */
itb_status_t itb_decrypt_auth(const itb_seed_t *noise,
                              const itb_seed_t *data,
                              const itb_seed_t *start,
                              const itb_mac_t *mac,
                              const void *ciphertext, size_t ciphertext_len,
                              uint8_t **out_buf, size_t *out_len);

/* ------------------------------------------------------------------ */
/* Cipher (Triple Ouroboros — seven seeds)                             */
/* ------------------------------------------------------------------ */
/*
 * Splits plaintext across three interleaved snake payloads. The on-wire
 * ciphertext format is the same shape as itb_encrypt(); only the
 * internal split / interleave differs. All seven seeds must share the
 * same native hash width and be pairwise distinct handles.
 */

itb_status_t itb_encrypt_triple(const itb_seed_t *noise,
                                const itb_seed_t *data1,
                                const itb_seed_t *data2,
                                const itb_seed_t *data3,
                                const itb_seed_t *start1,
                                const itb_seed_t *start2,
                                const itb_seed_t *start3,
                                const void *plaintext, size_t plaintext_len,
                                uint8_t **out_buf, size_t *out_len);

itb_status_t itb_decrypt_triple(const itb_seed_t *noise,
                                const itb_seed_t *data1,
                                const itb_seed_t *data2,
                                const itb_seed_t *data3,
                                const itb_seed_t *start1,
                                const itb_seed_t *start2,
                                const itb_seed_t *start3,
                                const void *ciphertext, size_t ciphertext_len,
                                uint8_t **out_buf, size_t *out_len);

itb_status_t itb_encrypt_auth_triple(const itb_seed_t *noise,
                                     const itb_seed_t *data1,
                                     const itb_seed_t *data2,
                                     const itb_seed_t *data3,
                                     const itb_seed_t *start1,
                                     const itb_seed_t *start2,
                                     const itb_seed_t *start3,
                                     const itb_mac_t *mac,
                                     const void *plaintext, size_t plaintext_len,
                                     uint8_t **out_buf, size_t *out_len);

itb_status_t itb_decrypt_auth_triple(const itb_seed_t *noise,
                                     const itb_seed_t *data1,
                                     const itb_seed_t *data2,
                                     const itb_seed_t *data3,
                                     const itb_seed_t *start1,
                                     const itb_seed_t *start2,
                                     const itb_seed_t *start3,
                                     const itb_mac_t *mac,
                                     const void *ciphertext, size_t ciphertext_len,
                                     uint8_t **out_buf, size_t *out_len);

/*
 * Releases a buffer allocated by any of the cipher entry points. NULL
 * is accepted (no-op). Wraps free() so applications that interpose
 * malloc / free see a single cross-binding-friendly entry point and
 * audit-time tooling has a single deallocation site to inspect.
 */
void itb_buffer_free(uint8_t *buf);

/* ------------------------------------------------------------------ */
/* Encryptor (Easy Mode)                                                */
/* ------------------------------------------------------------------ */
/*
 * High-level encryptor wrapper over the libitb `easy/` Go sub-package.
 * One constructor call replaces the lower-level seven-line setup
 * ceremony (hash factory, three or seven seeds, MAC closure,
 * container-config wiring) and returns a handle that owns its own
 * per-instance Config snapshot. Two encryptors with different settings
 * can be used in parallel without cross-contamination of the
 * process-wide ITB configuration.
 *
 * Output-buffer cache. The cipher methods (itb_encryptor_encrypt /
 * itb_encryptor_decrypt / itb_encryptor_encrypt_auth /
 * itb_encryptor_decrypt_auth) reuse a per-encryptor malloc'd buffer
 * as the libitb FFI write target so the size-probe round-trip is
 * skipped on the steady-state hot path; the buffer grows on demand
 * and survives between calls. Each cipher call hands the caller a
 * **freshly malloc'd user-owned copy** of the result via *out_buf,
 * which the caller releases with **itb_buffer_free()**. Same ownership
 * contract as the low-level itb_encrypt / itb_decrypt entry points;
 * the only difference is the elimination of the per-call FFI probe
 * round-trip, which is what makes the encryptor's hot path faster.
 * The cached bytes are zeroed on grow / close / free.
 *
 * Threading. Cipher methods write into the per-instance output cache
 * and are **not safe** to invoke concurrently against the same
 * encryptor — the cache pointer / capacity races with another
 * thread's cipher call. Per-instance setters (itb_encryptor_set_*)
 * and persistence calls (itb_encryptor_export / itb_encryptor_import)
 * likewise require external synchronisation when issued against the
 * same encryptor from multiple threads. Distinct encryptor handles,
 * each owned by one thread, run independently against the libitb
 * worker pool. The low-level free functions in this header
 * (itb_encrypt / itb_decrypt and the Triple variants) ARE thread-safe
 * because each call allocates its own output buffer; only the
 * encryptor-owned cache forces per-instance serialisation.
 *
 * Default-MAC override. When the constructor's `mac_name` is NULL or
 * the empty string, the binding substitutes `"hmac-blake3"` before
 * forwarding to libitb. HMAC-BLAKE3 measures the lightest
 * authenticated-mode overhead in the Easy bench surface, so the
 * constructor-without-MAC path picks the lowest-cost authenticated
 * MAC by default. To select a different MAC (e.g. "kmac256"), pass
 * the canonical MAC name explicitly.
 *
 * Mode `mode`. `1` = Single Ouroboros (3 seeds — noise / data /
 * start), `3` = Triple Ouroboros (7 seeds — noise + 3 pairs of data /
 * start). Other values surface as ITB_BAD_INPUT pre-FFI.
 *
 * Auto-couple semantics. Three rules govern the
 * BitSoup / LockSoup / LockSeed overlay across both Easy Mode
 * setters and the low-level process-wide knobs:
 *
 * 1. **Setter-level: LockSoup → BitSoup** (always, both modes).
 *    `itb_encryptor_set_lock_soup(e, non-zero)` auto-engages
 *    cfg.BitSoup = 1. `itb_encryptor_set_lock_seed(e, 1)` auto-engages
 *    cfg.BitSoup = 1 + cfg.LockSoup = 1 (the dedicated lockSeed has
 *    no wire effect without the overlay).
 *
 * 2. **Mode-dependent dispatch: Single Ouroboros activates the
 *    overlay if EITHER flag is set.** In mode = 1, the Go-side
 *    `splitForSingle` (bitsoup.go:1054-1057) engages the lock-soup
 *    overlay if either `cfg.BitSoup == 1` OR `cfg.LockSoup == 1`.
 *    Practical effect: in Single Ouroboros, calling
 *    `itb_encryptor_set_bit_soup(e, 1)` alone activates the
 *    lock-soup overlay at encrypt time even though cfg.LockSoup
 *    stays 0. In Triple Ouroboros (mode = 3), bit-soup and
 *    lock-soup are independently meaningful — bit-soup alone
 *    splits payload bits without the PRF-keyed permutation
 *    overlay. The same rule applies to the process-wide
 *    `itb_set_bit_soup` / `itb_set_lock_soup` knobs (they back the
 *    same flags `splitForSingle` consults).
 *
 * 3. **Off-direction coercion while LockSeed active.** If cfg.LockSeed
 *    == 1, calling `itb_encryptor_set_bit_soup(e, 0)` or
 *    `itb_encryptor_set_lock_soup(e, 0)` is silently coerced to 1 to
 *    keep the overlay engaged on the dedicated lockSeed channel; call
 *    `itb_encryptor_set_lock_seed(e, 0)` first to detach the lockSeed
 *    and fully disengage. This is intentional libitb behaviour
 *    propagated through the binding without filtering.
 */

/*
 * Forward-declared opaque encryptor handle. Concrete layout lives in
 * src/internal.h.
 */
typedef struct itb_encryptor itb_encryptor_t;

/* ---- Constructors ------------------------------------------------- */

/*
 * Constructs a fresh encryptor.
 *
 * `primitive` is a canonical hash name from itb_hash_name() (e.g.
 * "blake3", "areion512"). NULL selects the libitb default ("areion512").
 *
 * `key_bits` is the ITB key width in bits (512, 1024, 2048; multiple of
 * the primitive's native hash width). `0` selects the libitb default
 * (1024).
 *
 * `mac_name` is a canonical MAC name from itb_mac_name(). **NULL or the
 * empty string** triggers the binding-side default to `"hmac-blake3"`.
 *
 * `mode` is `1` (Single Ouroboros) or `3` (Triple Ouroboros). Other
 * values return ITB_BAD_INPUT pre-FFI.
 *
 * On success, *out is populated with a freshly-constructed encryptor
 * handle which the caller must release with itb_encryptor_free(). On
 * failure, *out is set to NULL.
 */
itb_status_t itb_encryptor_new(const char *primitive, int key_bits,
                               const char *mac_name, int mode,
                               itb_encryptor_t **out);

/*
 * Mixed-primitive Single-Ouroboros constructor — selects per-slot PRF
 * primitives independently.
 *
 * `prim_n` / `prim_d` / `prim_s` cover the noise / data / start slots
 * (all required, not NULL). `prim_l` is the optional dedicated lockSeed
 * primitive — pass NULL or "" for "no lockSeed primitive" (libitb engages
 * a dedicated lockSeed only when bit_soup or lock_soup is also enabled).
 * When `prim_l` is non-NULL and non-empty, a 4th seed slot is allocated
 * under that primitive and BitSoup + LockSoup auto-couple on the
 * on-direction.
 *
 * All four primitive names must resolve to the same native hash width
 * via the libitb registry; mixed widths surface the libitb panic message
 * via itb_last_error().
 *
 * Default-MAC override applies (see itb_encryptor_new).
 */
itb_status_t itb_encryptor_new_mixed(const char *prim_n,
                                     const char *prim_d,
                                     const char *prim_s,
                                     const char *prim_l,
                                     int key_bits,
                                     const char *mac_name,
                                     itb_encryptor_t **out);

/*
 * Triple-Ouroboros counterpart of itb_encryptor_new_mixed. Accepts
 * seven per-slot primitive names (noise + 3 data + 3 start) plus the
 * optional `prim_l` lockSeed primitive.
 *
 * Default-MAC override applies (see itb_encryptor_new).
 */
itb_status_t itb_encryptor_new_mixed3(const char *prim_n,
                                      const char *prim_d1,
                                      const char *prim_d2,
                                      const char *prim_d3,
                                      const char *prim_s1,
                                      const char *prim_s2,
                                      const char *prim_s3,
                                      const char *prim_l,
                                      int key_bits,
                                      const char *mac_name,
                                      itb_encryptor_t **out);

/* ---- Lifecycle ---------------------------------------------------- */

/*
 * Zeroes the encryptor's PRF / MAC / seed material on the Go side and
 * wipes the per-encryptor output cache. Idempotent — repeated close
 * calls return ITB_OK without reaching libitb. The wrapper struct
 * itself remains valid (the caller still holds the pointer); subsequent
 * calls on the closed encryptor (cipher / setters / getters / persist)
 * return ITB_EASY_CLOSED. Use itb_encryptor_free to deallocate the
 * wrapper.
 */
itb_status_t itb_encryptor_close(itb_encryptor_t *e);

/*
 * Releases the underlying libitb handle (if still held), zeroes the
 * cached output buffer, and deallocates the wrapper struct. NULL is
 * accepted (no-op). Idempotent against a previously-closed encryptor —
 * skip the libitb call when the handle was already released by close.
 */
void itb_encryptor_free(itb_encryptor_t *e);

/* ---- Cipher entry points ----------------------------------------- */
/*
 * Each cipher entry point returns a **freshly malloc'd user-owned
 * buffer** via *out_buf with the visible length in *out_len. The
 * caller releases the buffer with itb_buffer_free(). Empty plaintext
 * / ciphertext is rejected by libitb itself with ITB_ENCRYPT_FAILED
 * (mirror policy of the low-level itb_encrypt entry point above). On
 * error *out_buf is NULL and itb_last_error() carries the diagnostic.
 * The encryptor's internal cache (the libitb FFI write target) is
 * invisible to the caller and lives across calls; what reaches the
 * caller is always a fresh copy.
 */

/* Encrypts `plaintext` using the encryptor's configured primitive /
 * key_bits / mode. Plain mode — no MAC tag attached. */
itb_status_t itb_encryptor_encrypt(itb_encryptor_t *e,
                                   const void *plaintext, size_t plaintext_len,
                                   uint8_t **out_buf, size_t *out_len);

/* Decrypts ciphertext produced by itb_encryptor_encrypt under the same
 * encryptor (after a matching import_state on a fresh-constructed
 * encryptor). */
itb_status_t itb_encryptor_decrypt(itb_encryptor_t *e,
                                   const void *ciphertext, size_t ciphertext_len,
                                   uint8_t **out_buf, size_t *out_len);

/* Encrypts and attaches a MAC tag using the encryptor's bound MAC
 * closure. */
itb_status_t itb_encryptor_encrypt_auth(itb_encryptor_t *e,
                                        const void *plaintext, size_t plaintext_len,
                                        uint8_t **out_buf, size_t *out_len);

/* Verifies and decrypts ciphertext produced by
 * itb_encryptor_encrypt_auth. Returns ITB_MAC_FAILURE on tampered
 * ciphertext or wrong MAC key. */
itb_status_t itb_encryptor_decrypt_auth(itb_encryptor_t *e,
                                        const void *ciphertext, size_t ciphertext_len,
                                        uint8_t **out_buf, size_t *out_len);

/* ---- Per-instance configuration setters --------------------------- */

/* Override the nonce size. Valid values: 128, 256, 512. Mutates only
 * this encryptor's Config copy; process-wide itb_set_nonce_bits is
 * unaffected. */
itb_status_t itb_encryptor_set_nonce_bits(itb_encryptor_t *e, int n);

/* Override the CSPRNG barrier-fill margin. Valid values: 1, 2, 4, 8,
 * 16, 32. Asymmetric — receiver does not need the same value as
 * sender. */
itb_status_t itb_encryptor_set_barrier_fill(itb_encryptor_t *e, int n);

/* `0` = byte-level split (default); non-zero = bit-level Bit Soup
 * split. Mode-dependent overlay engagement: in Single Ouroboros
 * (mode = 1), enabling bit-soup activates the lock-soup overlay at
 * encrypt time even though cfg.LockSoup stays 0; in Triple
 * Ouroboros (mode = 3), bit-soup operates independently of
 * lock-soup. While a dedicated lockSeed is active (cfg.LockSeed
 * == 1) the Go-side easy package coerces `mode == 0` to `1` to
 * keep the overlay engaged. */
itb_status_t itb_encryptor_set_bit_soup(itb_encryptor_t *e, int mode);

/* `0` = off (default); non-zero = on. Auto-couples BitSoup=1 on
 * this encryptor (always, both modes — Lock Soup layers on top of
 * bit soup). */
itb_status_t itb_encryptor_set_lock_soup(itb_encryptor_t *e, int mode);

/* `0` = off; `1` = on (allocates a dedicated lockSeed and routes the
 * bit-permutation overlay through it; auto-couples LockSoup=1 +
 * BitSoup=1). Calling after the first encrypt returns
 * ITB_EASY_LOCKSEED_AFTER_ENCRYPT. */
itb_status_t itb_encryptor_set_lock_seed(itb_encryptor_t *e, int mode);

/* Per-instance streaming chunk-size override (`0` = auto-detect via
 * `itb.ChunkSize` on the Go side). */
itb_status_t itb_encryptor_set_chunk_size(itb_encryptor_t *e, int n);

/* ---- Read-only field accessors ------------------------------------ */

/* Writes the canonical primitive name bound at construction (NUL-
 * stripped). Two-call probe pattern — see itb_version. */
itb_status_t itb_encryptor_primitive(const itb_encryptor_t *e,
                                     char *out, size_t cap, size_t *out_len);

/* Writes the canonical MAC name bound at construction (NUL-stripped). */
itb_status_t itb_encryptor_mac_name(const itb_encryptor_t *e,
                                    char *out, size_t cap, size_t *out_len);

/*
 * Writes the canonical hash primitive name bound to the given seed
 * slot (NUL-stripped). Slot ordering is canonical — `0` = noiseSeed,
 * then dataSeed{,1..3}, then startSeed{,1..3}, with the optional
 * dedicated lockSeed at the trailing slot. For single-primitive
 * encryptors every slot returns the same itb_encryptor_primitive
 * value; for encryptors built via itb_encryptor_new_mixed{,3} each
 * slot returns its independently-chosen primitive name.
 */
itb_status_t itb_encryptor_primitive_at(const itb_encryptor_t *e, int slot,
                                        char *out, size_t cap, size_t *out_len);

/* Returns the ITB key width in bits via *out_value. */
itb_status_t itb_encryptor_key_bits(const itb_encryptor_t *e, int *out_value);

/* Returns 1 (Single) or 3 (Triple) via *out_value. */
itb_status_t itb_encryptor_mode(const itb_encryptor_t *e, int *out_value);

/* Returns the number of seed slots: 3 (Single without LockSeed),
 * 4 (Single with LockSeed), 7 (Triple without LockSeed), 8 (Triple
 * with LockSeed). */
itb_status_t itb_encryptor_seed_count(const itb_encryptor_t *e, int *out_value);

/*
 * Returns the live nonce size in bits — either the value from the
 * most recent itb_encryptor_set_nonce_bits call, or the process-wide
 * itb_get_nonce_bits reading at construction time when no per-instance
 * override has been issued.
 */
itb_status_t itb_encryptor_nonce_bits(const itb_encryptor_t *e, int *out_value);

/*
 * Returns the per-instance ciphertext-chunk header size in bytes
 * (nonce + 2-byte width + 2-byte height). Tracks this encryptor's own
 * itb_encryptor_nonce_bits, NOT the process-wide itb_header_size.
 */
itb_status_t itb_encryptor_header_size(const itb_encryptor_t *e, int *out_value);

/*
 * Returns 1 (true) when the encryptor's primitive uses fixed PRF keys
 * per seed slot (every shipped primitive except `siphash24`), 0
 * otherwise.
 */
itb_status_t itb_encryptor_has_prf_keys(const itb_encryptor_t *e, int *out_value);

/*
 * Returns 1 (true) when the encryptor was constructed via
 * itb_encryptor_new_mixed / itb_encryptor_new_mixed3, 0 for
 * single-primitive encryptors built via itb_encryptor_new.
 */
itb_status_t itb_encryptor_is_mixed(const itb_encryptor_t *e, int *out_value);

/*
 * Per-instance counterpart of itb_parse_chunk_len. Inspects a chunk
 * header (the fixed-size [nonce(N) || width(2) || height(2)] prefix
 * where N comes from this encryptor's nonce_bits) and returns the
 * total chunk length on the wire. Surfaces ITB_BAD_INPUT on too-short
 * buffer / zero dimensions / overflow.
 */
itb_status_t itb_encryptor_parse_chunk_len(const itb_encryptor_t *e,
                                           const void *header, size_t header_len,
                                           size_t *out_chunk_len);

/* ---- Material getters (defensive copies) -------------------------- */

/*
 * Writes the uint64 components of one seed slot into `out`. Two-call
 * probe (count-of-uint64 in *out_count, not byte count). Slot index
 * follows the canonical ordering: Single = [noise, data, start];
 * Triple = [noise, data1, data2, data3, start1, start2, start3]; the
 * dedicated lockSeed slot, when present, is appended at the trailing
 * index.
 */
itb_status_t itb_encryptor_seed_components(const itb_encryptor_t *e, int slot,
                                           uint64_t *out, size_t cap_count,
                                           size_t *out_count);

/*
 * Writes the fixed PRF key bytes for one seed slot into `out`. Two-call
 * probe pattern. SipHash-2-4 has no fixed PRF keys — *out_len comes
 * back as 0; consult itb_encryptor_has_prf_keys first.
 */
itb_status_t itb_encryptor_prf_key(const itb_encryptor_t *e, int slot,
                                   uint8_t *out, size_t cap, size_t *out_len);

/* Writes the encryptor's MAC fixed key into `out`. Two-call probe. */
itb_status_t itb_encryptor_mac_key(const itb_encryptor_t *e,
                                   uint8_t *out, size_t cap, size_t *out_len);

/* ---- Persistence (export / import) -------------------------------- */

/*
 * Serialises the encryptor's full state (PRF keys, seed components,
 * MAC key, dedicated lockSeed material when active) as a JSON blob.
 * The wrapper malloc()-s the buffer; the caller frees it with
 * itb_buffer_free().
 *
 * Per-instance configuration knobs (NonceBits, BarrierFill, BitSoup,
 * LockSoup, ChunkSize) are NOT carried in the v1 blob — both sides
 * communicate them via deployment config. LockSeed is carried because
 * activating it changes the structural seed count.
 */
itb_status_t itb_encryptor_export(const itb_encryptor_t *e,
                                  uint8_t **out_buf, size_t *out_len);

/*
 * Replaces the encryptor's PRF keys, seed components, MAC key, and
 * (optionally) dedicated lockSeed material with the values carried in
 * a JSON blob produced by a prior itb_encryptor_export call.
 *
 * On any failure the encryptor's pre-import state is unchanged (the
 * underlying Go-side import is transactional). Mismatch on primitive
 * / key_bits / mode / mac surfaces as ITB_EASY_MISMATCH; the offending
 * JSON field name is retrievable via itb_easy_last_mismatch_field.
 */
itb_status_t itb_encryptor_import(itb_encryptor_t *e,
                                  const void *blob, size_t blob_len);

/* ---- Free functions: peek + last-mismatch ------------------------- */

/*
 * Parses a state blob's metadata (primitive, key_bits, mode, mac_name)
 * without performing full validation, allowing a caller to inspect a
 * saved blob before constructing a matching encryptor.
 *
 * Both string out-buffers follow the two-call probe pattern: pass NULL
 * + 0 cap on the first call to discover required sizes via *prim_len /
 * *mac_len (visible lengths, NUL-stripped); on the second call pass
 * sufficient buffers to read both names. *key_bits_out / *mode_out
 * are populated on every successful round-trip.
 *
 * Surfaces ITB_EASY_MALFORMED on JSON parse failure / kind mismatch /
 * too-new version / unknown mode value.
 */
itb_status_t itb_easy_peek_config(const void *blob, size_t blob_len,
                                  char *prim_out, size_t prim_cap, size_t *prim_len,
                                  int *key_bits_out, int *mode_out,
                                  char *mac_out, size_t mac_cap, size_t *mac_len);

/*
 * Reads the offending JSON field name from the most recent
 * itb_encryptor_import call that returned ITB_EASY_MISMATCH on this
 * thread. Two-call probe pattern, NUL-stripped output. Empty string
 * when the most recent failure was not a mismatch.
 */
itb_status_t itb_easy_last_mismatch_field(char *out, size_t cap, size_t *out_len);

/* ------------------------------------------------------------------ */
/* Native Blob persistence                                              */
/* ------------------------------------------------------------------ */
/*
 * Width-typed blob containers — Blob128 / Blob256 / Blob512 — pack the
 * low-level encryptor material (per-seed hash key + components +
 * optional dedicated lockSeed + optional MAC key + name) plus the
 * captured process-wide configuration into one self-describing JSON
 * blob. Intended for the low-level encrypt / decrypt path where each
 * seed slot may carry a different primitive — the high-level
 * itb_encryptor_t wraps a narrower one-primitive-per-encryptor surface.
 *
 * The blob is mode-discriminated: itb_blob*_export packs Single
 * material, itb_blob*_export3 packs Triple material; itb_blob*_import
 * and itb_blob*_import3 are the corresponding receivers. A blob built
 * under one mode rejects the wrong importer with
 * ITB_BLOB_MODE_MISMATCH.
 *
 * Globals (NonceBits / BarrierFill / BitSoup / LockSoup) are captured
 * into the blob at export time and applied process-wide on import via
 * the same itb_set_nonce_bits / itb_set_barrier_fill / itb_set_bit_soup
 * / itb_set_lock_soup setters. The worker count and the global LockSeed
 * flag are not serialised — the former is a deployment knob, the latter
 * is irrelevant on the native path which consults
 * itb_seed_attach_lock_seed directly.
 *
 * Threading. Blob handles are not safe to share across threads without
 * external synchronisation — the per-handle setter / getter calls
 * mutate state on the libitb side. Distinct handles, each owned by
 * one thread, run independently.
 */

/* Forward-declared opaque blob handles. Concrete layout lives in
 * src/internal.h. */
typedef struct itb_blob128 itb_blob128_t;
typedef struct itb_blob256 itb_blob256_t;
typedef struct itb_blob512 itb_blob512_t;

/* Slot identifiers — mirror BlobSlot* in
 * cmd/cshared/internal/capi/blob_handles.go. */
#define ITB_BLOB_SLOT_N   0  /* shared: noiseSeed + KeyN              */
#define ITB_BLOB_SLOT_D   1  /* Single: dataSeed + KeyD               */
#define ITB_BLOB_SLOT_S   2  /* Single: startSeed + KeyS              */
#define ITB_BLOB_SLOT_L   3  /* optional any mode: dedicated lockSeed */
#define ITB_BLOB_SLOT_D1  4  /* Triple: dataSeed1 + KeyD1             */
#define ITB_BLOB_SLOT_D2  5
#define ITB_BLOB_SLOT_D3  6
#define ITB_BLOB_SLOT_S1  7  /* Triple: startSeed1 + KeyS1            */
#define ITB_BLOB_SLOT_S2  8
#define ITB_BLOB_SLOT_S3  9

/* Export option bitmask flags — mirror BlobOpt* in blob_handles.go.
 * Combine with bitwise OR; the trailing `opts` parameter on
 * itb_blob*_export / itb_blob*_export3 is the OR of zero or more of
 * these. */
#define ITB_BLOB_OPT_LOCKSEED  (1 << 0)  /* emit `l` slot (KeyL + components) */
#define ITB_BLOB_OPT_MAC       (1 << 1)  /* emit MAC key + name               */

/*
 * Generates the full per-width entry-point set for one blob width.
 * The macro expands to one declaration block per width, matching the
 * Rust binding's macro_rules! impl_blob_methods! pattern (each width
 * gets its own type-safe surface; no type erasure). Three expansions
 * cover Blob128 / Blob256 / Blob512.
 *
 * The macro name pasting (W##_new etc.) is hygienic — every generated
 * symbol is explicitly prefixed with `itb_blobW_` so collisions are
 * impossible across widths.
 */
#define ITB_DECLARE_BLOB_API(W, T)                                              \
    /* Constructs a fresh W-bit width Blob handle.                           */ \
    /* On success, *out is populated with the new handle which the caller   */ \
    /* must release with itb_blobW_free(). On failure, *out is NULL.        */ \
    itb_status_t itb_blob##W##_new(itb_blob##W##_t **out);                      \
    /* Releases the blob handle. NULL is accepted (no-op).                  */ \
    void itb_blob##W##_free(itb_blob##W##_t *b);                                \
    /* Returns the native hash width — 128, 256, or 512.                    */ \
    itb_status_t itb_blob##W##_width(const itb_blob##W##_t *b, int *out_value); \
    /* Returns the blob mode field — 0 = unset, 1 = Single, 3 = Triple.     */ \
    itb_status_t itb_blob##W##_mode(const itb_blob##W##_t *b, int *out_value);  \
    /* Stores the hash key bytes at the given slot. 256 / 512 widths        */ \
    /* require exactly 32 / 64 bytes; 128 width accepts variable lengths    */ \
    /* (empty for siphash24, 16 bytes for aescmac). Pass key=NULL,          */ \
    /* key_len=0 to clear.                                                  */ \
    itb_status_t itb_blob##W##_set_key(itb_blob##W##_t *b, int slot,            \
                                       const uint8_t *key, size_t key_len);    \
    /* Reads the hash key bytes from the given slot. Two-call probe (out=  */ \
    /* NULL, cap=0 first to discover required size in *out_len).            */ \
    itb_status_t itb_blob##W##_get_key(const itb_blob##W##_t *b, int slot,      \
                                       uint8_t *out, size_t cap,               \
                                       size_t *out_len);                        \
    /* Stores the seed components (uint64 array) at the given slot. Component */ \
    /* count must satisfy 8..MaxKeyBits/64 multiple-of-8 invariants —       */ \
    /* validation is deferred to export / import time.                      */ \
    itb_status_t itb_blob##W##_set_components(itb_blob##W##_t *b, int slot,     \
                                              const uint64_t *comps,            \
                                              size_t count);                    \
    /* Reads the seed components from the given slot. Two-call probe        */ \
    /* (count-of-uint64 in *out_count, not byte count).                     */ \
    itb_status_t itb_blob##W##_get_components(const itb_blob##W##_t *b, int slot, \
                                              uint64_t *out, size_t cap_count,  \
                                              size_t *out_count);               \
    /* Stores the optional MAC key bytes. Pass key=NULL or key_len=0 to     */ \
    /* clear a previously-set key.                                          */ \
    itb_status_t itb_blob##W##_set_mac_key(itb_blob##W##_t *b,                  \
                                           const uint8_t *key, size_t key_len); \
    /* Reads the MAC key bytes. Two-call probe; *out_len = 0 when no MAC    */ \
    /* is associated with the handle.                                       */ \
    itb_status_t itb_blob##W##_get_mac_key(const itb_blob##W##_t *b,            \
                                           uint8_t *out, size_t cap,            \
                                           size_t *out_len);                    \
    /* Stores the optional MAC name on the handle. Pass name=NULL or "" to */ \
    /* clear a previously-set name.                                         */ \
    itb_status_t itb_blob##W##_set_mac_name(itb_blob##W##_t *b,                 \
                                            const char *name);                  \
    /* Reads the MAC name from the handle. Two-call probe pattern,          */ \
    /* NUL-stripped output. Empty string when no MAC is associated.         */ \
    itb_status_t itb_blob##W##_get_mac_name(const itb_blob##W##_t *b,           \
                                            char *out, size_t cap,              \
                                            size_t *out_len);                    \
    /* Serialises the handle's Single-Ouroboros state into a JSON blob.    */ \
    /* `opts` is a bitmask of ITB_BLOB_OPT_LOCKSEED / ITB_BLOB_OPT_MAC.    */ \
    /* The wrapper malloc()-s the buffer; caller frees with                */ \
    /* itb_buffer_free().                                                   */ \
    itb_status_t itb_blob##W##_export(const itb_blob##W##_t *b, int opts,       \
                                      uint8_t **out_buf, size_t *out_len);     \
    /* Triple-Ouroboros counterpart of itb_blobW_export.                   */ \
    itb_status_t itb_blob##W##_export3(const itb_blob##W##_t *b, int opts,      \
                                       uint8_t **out_buf, size_t *out_len);    \
    /* Parses a Single-Ouroboros JSON blob, populates the handle's slots, */ \
    /* and applies the captured globals via the process-wide setters.     */ \
    /* Returns ITB_BLOB_MODE_MISMATCH on Triple-mode blob,                 */ \
    /* ITB_BLOB_MALFORMED on parse / shape failure,                        */ \
    /* ITB_BLOB_VERSION_TOO_NEW on a version field higher than this build */ \
    /* supports.                                                            */ \
    itb_status_t itb_blob##W##_import(itb_blob##W##_t *b,                       \
                                      const void *blob, size_t blob_len);      \
    /* Triple-Ouroboros counterpart of itb_blobW_import.                   */ \
    itb_status_t itb_blob##W##_import3(itb_blob##W##_t *b,                      \
                                       const void *blob, size_t blob_len);     \
    /* sentinel — keeps the macro a statement-list rather than ending in   */ \
    /* a stray semicolon at expansion sites                                 */ \
    typedef T itb_blob##W##_decl_sentinel_t

ITB_DECLARE_BLOB_API(128, int);
ITB_DECLARE_BLOB_API(256, int);
ITB_DECLARE_BLOB_API(512, int);

/* ------------------------------------------------------------------ */
/* Streams (chunked encrypt / decrypt over caller-owned I/O)            */
/* ------------------------------------------------------------------ */
/*
 * Streaming wrappers over the low-level itb_encrypt / itb_decrypt /
 * Triple variants. ITB ciphertexts cap at ~64 MB plaintext per chunk
 * (the underlying container size limit); streaming larger payloads
 * means slicing the input into chunk_size-sized blocks at the binding
 * layer, encrypting each through the regular FFI path, and
 * concatenating the results. The reverse operation walks a
 * concatenated chunk stream by reading the chunk header, calling
 * itb_parse_chunk_len to learn the chunk's body length, reading that
 * many bytes, and decrypting the single chunk.
 *
 * I/O contract. The caller supplies a (read_fn, user_ctx) pair for the
 * input source and a (write_fn, user_ctx) pair for the output sink.
 * The same user_ctx pointer is threaded through both callbacks so the
 * caller can carry state (file descriptor, std::ostream, in-memory
 * buffer, etc.) without globals. Read returns *out_n = 0 to signal
 * EOF; write must consume the full (buf, n) span before returning.
 *
 * Memory peak is bounded by chunk_size regardless of the total
 * payload length. The caller MUST pass `chunk_size > 0` — zero is
 * rejected with `ITB_BAD_INPUT` (matches the cross-binding contract).
 * `ITB_DEFAULT_CHUNK_SIZE` (16 MiB) is exposed as a recommended
 * starting value for callers without a domain-specific preference.
 *
 * Seed lifetime contract. Every Seed (and the optional MAC) handed to
 * a stream entry point must remain alive — un-freed — for the entire
 * call. The wrappers cache the raw libitb handles internally; freeing
 * an originating Seed mid-call would yank the handle out from under
 * the chunk loop (use-after-free in the FFI call). C relies on caller
 * discipline.
 *
 * Warning. Do not call itb_set_nonce_bits between calls on the same
 * stream pair. Each chunk is encrypted under the active nonce-size at
 * the moment it is flushed; switching nonce-bits mid-stream produces
 * a chunk header layout the paired decryptor cannot parse.
 */

/* Default chunk size — matches itb.DefaultChunkSize on the Go side
 * (16 MB), the size at which ITB's barrier-encoded container layout
 * stays well within the per-chunk pixel cap. Mirrors Rust's
 * DEFAULT_CHUNK_SIZE constant. */
#define ITB_DEFAULT_CHUNK_SIZE ((size_t) (16 * 1024 * 1024))

/*
 * Read callback signature.
 *
 * Fills `buf` with up to `cap` bytes from the caller-owned source and
 * reports the actual byte count via *out_n. EOF is signalled by
 * returning 0 with *out_n = 0. Returning a non-zero status code
 * aborts the stream operation and propagates back through
 * itb_stream_*; ITB_INTERNAL is the default surface code for "I/O
 * error from the caller's read_fn". `user_ctx` is the caller-supplied
 * context pointer threaded through the stream call.
 *
 * A short read (*out_n < cap with retval 0 and a subsequent non-zero
 * read available) is permitted — the chunk loop drains across
 * multiple read_fn calls — but the implementation must signal EOF
 * exactly once (*out_n = 0) when the source is exhausted.
 */
typedef int (*itb_stream_read_fn)(void *user_ctx,
                                  void *buf, size_t cap, size_t *out_n);

/*
 * Write callback signature.
 *
 * Consumes the full `(buf, n)` span and reports success via a 0
 * return value. Partial writes must be retried inside the callback
 * (the stream loop relies on write_fn being write_all-equivalent).
 * Returning a non-zero status code aborts the stream operation.
 * `user_ctx` is the caller-supplied context pointer threaded through
 * the stream call.
 */
typedef int (*itb_stream_write_fn)(void *user_ctx,
                                   const void *buf, size_t n);

/*
 * Reads plaintext from `read_fn` until EOF, encrypts in chunks of
 * `chunk_size` bytes (plain Single Ouroboros — routes through
 * `itb_encrypt`), and writes concatenated ITB chunks to `write_fn`.
 * `chunk_size` MUST be > 0 (returns `ITB_BAD_INPUT` on zero).
 *
 * `read_user_ctx` and `write_user_ctx` are independent — pass the
 * same pointer if the caller's context covers both directions, or
 * distinct pointers when read source and write sink are separate.
 *
 * Authenticated streams are not exposed in the free-function shape;
 * callers needing per-chunk MAC tagging build the chunk loop on
 * `itb_encryptor_encrypt_auth` directly. This matches the
 * cross-binding stream surface — none of the seven bindings expose a
 * MAC parameter on the stream free functions.
 */
itb_status_t itb_stream_encrypt(const itb_seed_t *noise,
                                const itb_seed_t *data,
                                const itb_seed_t *start,
                                itb_stream_read_fn read_fn, void *read_user_ctx,
                                itb_stream_write_fn write_fn, void *write_user_ctx,
                                size_t chunk_size);

/*
 * Reads concatenated ITB chunks from `read_fn` until EOF and writes
 * the recovered plaintext to `write_fn` (plain Single Ouroboros —
 * routes through `itb_decrypt`). The chunk-header size is snapshotted
 * at call entry; do not flip itb_set_nonce_bits during the call.
 *
 * `chunk_size` controls the read-buffer granularity and MUST be > 0
 * (returns `ITB_BAD_INPUT` on zero); the per-chunk decrypt path
 * consumes the accumulated buffer one full chunk at a time regardless
 * of chunk_size.
 */
itb_status_t itb_stream_decrypt(const itb_seed_t *noise,
                                const itb_seed_t *data,
                                const itb_seed_t *start,
                                itb_stream_read_fn read_fn, void *read_user_ctx,
                                itb_stream_write_fn write_fn, void *write_user_ctx,
                                size_t chunk_size);

/* Triple-Ouroboros (7-seed) counterpart of itb_stream_encrypt. */
itb_status_t itb_stream_encrypt_triple(const itb_seed_t *noise,
                                       const itb_seed_t *data1,
                                       const itb_seed_t *data2,
                                       const itb_seed_t *data3,
                                       const itb_seed_t *start1,
                                       const itb_seed_t *start2,
                                       const itb_seed_t *start3,
                                       itb_stream_read_fn read_fn,
                                       void *read_user_ctx,
                                       itb_stream_write_fn write_fn,
                                       void *write_user_ctx,
                                       size_t chunk_size);

/* Triple-Ouroboros (7-seed) counterpart of itb_stream_decrypt. */
itb_status_t itb_stream_decrypt_triple(const itb_seed_t *noise,
                                       const itb_seed_t *data1,
                                       const itb_seed_t *data2,
                                       const itb_seed_t *data3,
                                       const itb_seed_t *start1,
                                       const itb_seed_t *start2,
                                       const itb_seed_t *start3,
                                       itb_stream_read_fn read_fn,
                                       void *read_user_ctx,
                                       itb_stream_write_fn write_fn,
                                       void *write_user_ctx,
                                       size_t chunk_size);

/* ------------------------------------------------------------------ */
/* Authenticated streams (Streaming AEAD)                              */
/* ------------------------------------------------------------------ */
/*
 * Streaming AEAD wrappers built on top of per-chunk libitb entry
 * points. The on-wire transcript carries a 32-byte CSPRNG `stream_id`
 * prefix once at stream start, followed by a sequence of ITB chunks
 * each authenticated under the (stream_id, cumulative_pixel_offset,
 * final_flag) binding tuple. The encoder helper generates the
 * `stream_id`, writes the prefix, and tags the trailing chunk with
 * `final_flag = true`; the decoder helper reads the prefix once and
 * verifies every chunk under the same `stream_id`. Variants closed
 * by the binding-side helper:
 *
 *   - Reorder of two chunks                  -> ITB_MAC_FAILURE
 *   - Replay within a single stream          -> ITB_MAC_FAILURE
 *   - Cross-stream replay sharing PRF/MAC    -> ITB_MAC_FAILURE
 *   - Truncate-tail (drop last chunk)        -> ITB_STREAM_TRUNCATED
 *   - Extra chunk past the terminating one   -> ITB_STREAM_AFTER_FINAL
 *   - Stream-prefix tamper (32-byte header)  -> ITB_MAC_FAILURE
 *
 * The MAC handle (one per stream, allocated via itb_mac_new) is reused
 * across every chunk; the helper does not free it. Same I/O contract,
 * memory peak, and chunk_size > 0 preflight as the plain stream
 * helpers above. Empty plaintext is permitted — a zero-byte stream
 * emits the 32-byte `stream_id` prefix followed by a single
 * terminating chunk carrying len=0 plaintext.
 */

/*
 * Reads plaintext from `read_fn` until EOF, encrypts in chunks of
 * `chunk_size` bytes (Single Ouroboros, Streaming AEAD), and writes
 * the concatenated `stream_id || chunk_0 || chunk_1 || ...` transcript
 * to `write_fn`. `chunk_size` MUST be > 0.
 */
itb_status_t itb_stream_encrypt_auth(const itb_seed_t *noise,
                                     const itb_seed_t *data,
                                     const itb_seed_t *start,
                                     const itb_mac_t *mac,
                                     itb_stream_read_fn read_fn, void *read_user_ctx,
                                     itb_stream_write_fn write_fn, void *write_user_ctx,
                                     size_t chunk_size);

/*
 * Reads a Streaming AEAD transcript from `read_fn` until EOF and
 * writes the recovered plaintext to `write_fn`. Returns
 * ITB_STREAM_TRUNCATED when input exhausts without a terminating
 * chunk, ITB_STREAM_AFTER_FINAL when bytes follow the terminator,
 * and ITB_MAC_FAILURE on any per-chunk MAC mismatch. `chunk_size`
 * controls the read-buffer granularity and MUST be > 0.
 */
itb_status_t itb_stream_decrypt_auth(const itb_seed_t *noise,
                                     const itb_seed_t *data,
                                     const itb_seed_t *start,
                                     const itb_mac_t *mac,
                                     itb_stream_read_fn read_fn, void *read_user_ctx,
                                     itb_stream_write_fn write_fn, void *write_user_ctx,
                                     size_t chunk_size);

/* Triple-Ouroboros (7-seed) counterpart of itb_stream_encrypt_auth. */
itb_status_t itb_stream_encrypt_auth_triple(const itb_seed_t *noise,
                                            const itb_seed_t *data1,
                                            const itb_seed_t *data2,
                                            const itb_seed_t *data3,
                                            const itb_seed_t *start1,
                                            const itb_seed_t *start2,
                                            const itb_seed_t *start3,
                                            const itb_mac_t *mac,
                                            itb_stream_read_fn read_fn,
                                            void *read_user_ctx,
                                            itb_stream_write_fn write_fn,
                                            void *write_user_ctx,
                                            size_t chunk_size);

/* Triple-Ouroboros (7-seed) counterpart of itb_stream_decrypt_auth. */
itb_status_t itb_stream_decrypt_auth_triple(const itb_seed_t *noise,
                                            const itb_seed_t *data1,
                                            const itb_seed_t *data2,
                                            const itb_seed_t *data3,
                                            const itb_seed_t *start1,
                                            const itb_seed_t *start2,
                                            const itb_seed_t *start3,
                                            const itb_mac_t *mac,
                                            itb_stream_read_fn read_fn,
                                            void *read_user_ctx,
                                            itb_stream_write_fn write_fn,
                                            void *write_user_ctx,
                                            size_t chunk_size);

/* ------------------------------------------------------------------ */
/* Encryptor (Easy Mode) — Streaming AEAD                              */
/* ------------------------------------------------------------------ */
/*
 * Encryptor-bound Streaming AEAD helpers. Reuse the encryptor's
 * configured primitive / key-bits / mode / MAC closure; the per-call
 * binding components (stream_id, cumulative_pixel_offset, final_flag)
 * are managed by the helper internally. Encryptor's closed-state
 * preflight (ITB_EASY_CLOSED) applies. Otherwise identical contract
 * to the seed-based itb_stream_encrypt_auth / itb_stream_decrypt_auth
 * — chunk_size > 0, callback I/O, ITB_STREAM_TRUNCATED /
 * ITB_STREAM_AFTER_FINAL on the two end-of-stream failure modes.
 */

itb_status_t itb_encryptor_stream_encrypt_auth(itb_encryptor_t *e,
                                               itb_stream_read_fn read_fn,
                                               void *read_user_ctx,
                                               itb_stream_write_fn write_fn,
                                               void *write_user_ctx,
                                               size_t chunk_size);

itb_status_t itb_encryptor_stream_decrypt_auth(itb_encryptor_t *e,
                                               itb_stream_read_fn read_fn,
                                               void *read_user_ctx,
                                               itb_stream_write_fn write_fn,
                                               void *write_user_ctx,
                                               size_t chunk_size);

/* ------------------------------------------------------------------ */
/* Format-deniability wrapper                                          */
/* ------------------------------------------------------------------ */
/*
 * Outer keystream-cipher envelope that hides the on-wire ITB byte
 * pattern (per-chunk header / 32-byte streamID prefix / container
 * layout) under one of three generic stream ciphers — AES-128-CTR,
 * ChaCha20 (RFC8439), or SipHash-2-4 in CTR mode. Wire format is
 * `nonce || keystream-XOR(bytestream)`, indistinguishable from any
 * generic stream-cipher payload by surface pattern. ITB's content-
 * deniability is unchanged; the AEAD path's integrity is unchanged.
 * The wrap exists for **format-deniability ONLY** — adding a MAC at
 * this layer would defeat the goal (the wire would pattern-match an
 * AEAD construction's tag-bearing format, not a generic stream
 * cipher).
 *
 * Two flavours of helpers, picked per use case:
 *
 *   1. itb_wrap / itb_unwrap (Single Message, allocation) — seals the
 *      whole ITB ciphertext blob as one wrap. Suitable for any
 *      single-message Encrypt / EncryptAuth output. Wire =
 *      `nonce || keystream-XOR(blob)`.
 *
 *      itb_wrap_in_place / itb_unwrap_in_place are zero-allocation
 *      variants that XOR the caller's blob / wire buffer in place.
 *      Suitable for hot paths where the caller has just produced an
 *      ITB ciphertext and will not re-read it.
 *
 *   2. itb_wrap_stream_writer_* / itb_unwrap_stream_reader_*
 *      (streaming) — opens a stateful wrap session. The constructor
 *      draws a fresh CSPRNG nonce and returns it via out_nonce so the
 *      caller can emit it once at stream start (typically as the wire
 *      prefix). Subsequent _update calls XOR caller bytes through the
 *      keystream; the keystream counter advances monotonically across
 *      every byte fed into the session. Suitable for the
 *      Streaming AEAD IO-Driven flow (the entire bytestream emitted
 *      by ITB's stream encoder gets wrapped end-to-end) and for the
 *      User-Driven Loop (caller-side framing — e.g. per-chunk u32_LE
 *      length prefixes — is also written through the wrap session so
 *      the framing bytes pass through the keystream XOR alongside the
 *      ITB ciphertext bodies).
 *
 * Outer-cipher key sizes (16 / 32 / 16 bytes) and nonce sizes (16 /
 * 12 / 16 bytes) match the libitb wrapper Go-side wrapper.KeySize
 * and wrapper.NonceSize. The outer key MAY be reused across many
 * streams provided each stream uses a fresh CSPRNG nonce — this is
 * the standard CTR mode safety contract; the helpers always generate
 * a fresh nonce internally, so caller-side discipline is reduced to
 * "do not reuse the same (key, nonce) across distinct streams".
 *
 * Threading. The Single Message itb_wrap / itb_unwrap / itb_wrap_in_place
 * / itb_unwrap_in_place are thread-safe: each call constructs an
 * outer cipher session of its own and the libitb keystream
 * constructor draws a fresh CSPRNG nonce per call. The streaming
 * itb_wrap_stream_writer_t / itb_unwrap_stream_reader_t handles are
 * single-feeder — every _update call advances the underlying
 * keystream counter; concurrent _update calls on the same handle
 * race. Distinct handles run independently.
 */

/*
 * Outer cipher selector. Use the named enum constants in caller code
 * — direct integer comparisons against the enum value are part of the
 * stable ABI surface (the order matches wrapper.CipherNames in the
 * Go-side wrapper package).
 */
typedef enum itb_wrapper_cipher {
    ITB_WRAPPER_CIPHER_AES_128_CTR = 0,
    ITB_WRAPPER_CIPHER_CHACHA20    = 1,
    ITB_WRAPPER_CIPHER_SIPHASH24   = 2
} itb_wrapper_cipher_t;

/*
 * Returns the canonical short name of the named outer cipher ("aes" /
 * "chacha" / "siphash") as an interned NUL-terminated C string. The
 * pointer is owned by libitb_c and stays valid for the lifetime of the
 * process; callers MUST NOT free it. Returns NULL for any value not in
 * itb_wrapper_cipher_t.
 */
const char *itb_wrapper_cipher_name(itb_wrapper_cipher_t cipher);

/*
 * Returns the byte length of the keystream-cipher key for the named
 * outer cipher via *out_size: 16 for AES-128-CTR / SipHash-CTR; 32
 * for ChaCha20. Returns ITB_BAD_INPUT for an unknown cipher value.
 */
itb_status_t itb_wrapper_key_size(itb_wrapper_cipher_t cipher,
                                  size_t *out_size);

/*
 * Returns the on-wire nonce length the named outer cipher emits per
 * stream via *out_size: 16 for AES-128-CTR / SipHash-CTR; 12 for
 * ChaCha20. Returns ITB_BAD_INPUT for an unknown cipher value.
 */
itb_status_t itb_wrapper_nonce_size(itb_wrapper_cipher_t cipher,
                                    size_t *out_size);

/*
 * Generates a fresh CSPRNG outer cipher key of the size required by
 * `cipher` (via itb_wrapper_key_size). On success, *out_key receives
 * a freshly malloc'd buffer the caller releases via itb_buffer_free();
 * *out_key_len receives the byte length. On failure *out_key is NULL
 * and *out_key_len is 0; itb_last_error() carries the diagnostic.
 *
 * Uses the system CSPRNG (getrandom(2) on Linux, the equivalent on
 * other platforms — every supported host has a usable CSPRNG by
 * standard practice). Falls back to ITB_INTERNAL on a CSPRNG read
 * failure (very rare; signals a misconfigured kernel).
 */
itb_status_t itb_wrapper_generate_key(itb_wrapper_cipher_t cipher,
                                      uint8_t **out_key, size_t *out_key_len);

/*
 * Single Message wrap. Seals `blob` under `cipher` with a fresh per-call
 * CSPRNG nonce; *out_wire receives a freshly malloc'd buffer holding
 * `nonce || keystream-XOR(blob)`. Caller releases via itb_buffer_free().
 *
 * Required out capacity is itb_wrapper_nonce_size(cipher) + blob_len;
 * the wrapper handles the allocation. Empty blob is permitted —
 * the wire becomes `nonce` alone (length-checked on the Go side).
 */
itb_status_t itb_wrap(itb_wrapper_cipher_t cipher,
                      const uint8_t *key, size_t key_len,
                      const uint8_t *blob, size_t blob_len,
                      uint8_t **out_wire, size_t *out_wire_len);

/*
 * Single Message unwrap. Reads the leading itb_wrapper_nonce_size(cipher)
 * bytes of `wire` as the per-stream nonce, XOR-decrypts the remainder
 * under (key, nonce). *out_blob receives a freshly malloc'd buffer
 * holding the recovered blob; caller releases via itb_buffer_free().
 * Returns ITB_BAD_INPUT when wire_len < nonce_size.
 */
itb_status_t itb_unwrap(itb_wrapper_cipher_t cipher,
                        const uint8_t *key, size_t key_len,
                        const uint8_t *wire, size_t wire_len,
                        uint8_t **out_blob, size_t *out_blob_len);

/*
 * In-place Single Message wrap. XORs `blob` under a freshly drawn per-
 * call CSPRNG nonce; the caller-supplied `out_nonce` buffer (capacity
 * `nonce_cap`) receives the nonce bytes. The caller then emits
 * `nonce || mutated-blob` to the wire (or composes a single buffer).
 *
 * `blob` is **MUTATED** in place. Use itb_wrap when the caller's
 * plaintext must be preserved.
 *
 * `nonce_cap` must be >= itb_wrapper_nonce_size(cipher) — pass exactly
 * that size for the typical case. Returns ITB_BAD_INPUT when the
 * nonce buffer is too small.
 */
itb_status_t itb_wrap_in_place(itb_wrapper_cipher_t cipher,
                               const uint8_t *key, size_t key_len,
                               uint8_t *blob, size_t blob_len,
                               uint8_t *out_nonce, size_t nonce_cap);

/*
 * In-place Single Message unwrap. Strips the leading
 * itb_wrapper_nonce_size(cipher) bytes from `wire` and XOR-decrypts
 * the remainder in place. The decrypted body occupies
 * `wire[nonce_size .. wire_len)`; the leading nonce prefix is left
 * unchanged. `wire` is **MUTATED** in place.
 *
 * Returns ITB_BAD_INPUT when wire_len < nonce_size.
 */
itb_status_t itb_unwrap_in_place(itb_wrapper_cipher_t cipher,
                                 const uint8_t *key, size_t key_len,
                                 uint8_t *wire, size_t wire_len);

/*
 * Forward-declared opaque wrap-stream-writer handle. Concrete layout
 * lives in src/internal.h.
 */
typedef struct itb_wrap_stream_writer itb_wrap_stream_writer_t;

/*
 * Forward-declared opaque unwrap-stream-reader handle. Concrete layout
 * lives in src/internal.h.
 */
typedef struct itb_unwrap_stream_reader itb_unwrap_stream_reader_t;

/*
 * Allocates a fresh streaming wrap-encrypt handle. Draws a CSPRNG
 * nonce, opens a libitb wrap-stream session keyed by (cipher, key,
 * nonce), and writes the nonce bytes into `out_nonce` (capacity
 * `nonce_cap` >= itb_wrapper_nonce_size(cipher)).
 *
 * The caller emits the nonce once at stream start (typically as the
 * wire prefix) so the matching itb_unwrap_stream_reader_t can be
 * constructed against it. Subsequent itb_wrap_stream_writer_update
 * calls XOR caller plaintext through the keystream; the counter
 * advances monotonically across calls.
 *
 * Pair every successful itb_wrap_stream_writer_new with exactly one
 * itb_wrap_stream_writer_free call. On failure *out_w is NULL and a
 * non-OK status is returned.
 */
itb_status_t itb_wrap_stream_writer_new(itb_wrapper_cipher_t cipher,
                                        const uint8_t *key, size_t key_len,
                                        uint8_t *out_nonce, size_t nonce_cap,
                                        itb_wrap_stream_writer_t **out_w);

/*
 * XOR-encrypts `src[0..src_len)` into `dst[0..src_len)` under the
 * handle's keystream. `dst` MAY equal `src` (in-place mutation);
 * `dst_cap` must be >= src_len. Empty input (src_len == 0) is a
 * no-op and returns ITB_OK.
 *
 * Returns ITB_BAD_HANDLE when called after itb_wrap_stream_writer_free.
 */
itb_status_t itb_wrap_stream_writer_update(itb_wrap_stream_writer_t *w,
                                           const uint8_t *src, size_t src_len,
                                           uint8_t *dst, size_t dst_cap);

/*
 * Releases the wrap-encrypt streaming handle. NULL is accepted (no-op).
 * Idempotent — repeated free calls return without reaching libitb.
 */
void itb_wrap_stream_writer_free(itb_wrap_stream_writer_t *w);

/*
 * Allocates a fresh streaming unwrap-decrypt handle. Opens a libitb
 * wrap-stream session keyed by (cipher, key, wire_nonce); subsequent
 * itb_unwrap_stream_reader_update calls XOR caller wire bytes back
 * to plaintext under the keystream advancing from counter zero.
 *
 * `wire_nonce` is the per-stream nonce read off the wire (typically
 * the leading itb_wrapper_nonce_size(cipher) bytes). `nonce_len` must
 * equal that value or ITB_BAD_INPUT is returned.
 *
 * Pair every successful itb_unwrap_stream_reader_new with exactly one
 * itb_unwrap_stream_reader_free call. On failure *out_r is NULL.
 */
itb_status_t itb_unwrap_stream_reader_new(itb_wrapper_cipher_t cipher,
                                          const uint8_t *key, size_t key_len,
                                          const uint8_t *wire_nonce,
                                          size_t nonce_len,
                                          itb_unwrap_stream_reader_t **out_r);

/*
 * XOR-decrypts `src[0..src_len)` into `dst[0..src_len)` under the
 * handle's keystream. `dst` MAY equal `src` (in-place mutation);
 * `dst_cap` must be >= src_len. Empty input (src_len == 0) is a
 * no-op and returns ITB_OK.
 *
 * Returns ITB_BAD_HANDLE when called after itb_unwrap_stream_reader_free.
 */
itb_status_t itb_unwrap_stream_reader_update(itb_unwrap_stream_reader_t *r,
                                             const uint8_t *src, size_t src_len,
                                             uint8_t *dst, size_t dst_cap);

/*
 * Releases the unwrap-decrypt streaming handle. NULL is accepted
 * (no-op). Idempotent — repeated free calls return without reaching
 * libitb.
 */
void itb_unwrap_stream_reader_free(itb_unwrap_stream_reader_t *r);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ITB_H */
