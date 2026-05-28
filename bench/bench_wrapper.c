/*
 * bench_wrapper.c — format-deniability wrapper benchmarks for the C
 * binding.
 *
 * Mirrors `wrapper/bench_test.go` from the root repository, adapted
 * for the C binding asymmetry: the Streaming No MAC arm covers only
 * the User-Driven Loop variant (the C binding does not expose a
 * FILE* / file-like wrapper writer / reader pair for Non-AEAD
 * streaming).
 *
 * The outer-cipher palette covers every cipher in
 * PRIMITIVES_CANONICAL order (areion256, areion512, blake2b256,
 * blake2b512, blake2s, blake3, aescmac, siphash24, chacha20):
 *
 *   - Wrapper Only round-trip (16 MiB blob)              : 2 variants {Wrap, WrapInPlace} per cipher
 *   - Message Single — 4 modes × 2 dirs per cipher
 *   - Message Triple — 4 modes × 2 dirs per cipher
 *   - Streaming Single — 4 modes × 2 dirs per cipher
 *   - Streaming Triple — 4 modes × 2 dirs per cipher
 *
 * 4 message modes: easy-nomac / easy-auth / lowlevel-nomac /
 * lowlevel-auth.
 *
 * 4 streaming modes: aead-easy-io / aead-lowlevel-io /
 * noaead-easy-userloop / noaead-lowlevel-userloop.
 *
 * Both encrypt and decrypt are timed separately. Decrypt benches
 * refresh the working wire from a pristine copy each iteration —
 * the memcpy is included in the timed total, matching the
 * cross-binding convention.
 *
 * Run with:
 *
 *     make bench
 *     ./bench/build/bench_wrapper
 *
 *     ITB_BENCH_FILTER=BenchmarkWrapperOnly ./bench/build/bench_wrapper
 *
 * The harness emits one Go-bench-style line per case (name, iters,
 * ns/op, MB/s).
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "itb.h"

/* ----- Configuration ------------------------------------------------ */

/* Full outer-keystream palette in PRIMITIVES_CANONICAL order
 * (areion256, areion512, blake2b256, blake2b512, blake2s, blake3,
 * aescmac, siphash24, chacha20). */
static const itb_wrapper_cipher_t CIPHERS[] = {
    ITB_WRAPPER_CIPHER_AREION_256,
    ITB_WRAPPER_CIPHER_AREION_512,
    ITB_WRAPPER_CIPHER_BLAKE2B_256,
    ITB_WRAPPER_CIPHER_BLAKE2B_512,
    ITB_WRAPPER_CIPHER_BLAKE2S,
    ITB_WRAPPER_CIPHER_BLAKE3,
    ITB_WRAPPER_CIPHER_AES_128_CTR,
    ITB_WRAPPER_CIPHER_SIPHASH24,
    ITB_WRAPPER_CIPHER_CHACHA20,
};
static const char *const CIPHER_NAMES[] = {
    "areion256", "areion512", "blake2b256", "blake2b512", "blake2s",
    "blake3", "aescmac", "siphash24", "chacha20",
};
#define CIPHER_COUNT 9

#define WRAPPER_PAYLOAD_BYTES BENCH_PAYLOAD_16MB
#define MESSAGE_PAYLOAD_BYTES BENCH_PAYLOAD_16MB
#define STREAM_PAYLOAD_BYTES  ((size_t)(64u << 20))
#define STREAM_CHUNK_BYTES    ((size_t)(16u << 20))

#define BENCH_PRIMITIVE "areion512"
#define BENCH_KEY_BITS  1024
#define BENCH_MAC_NAME  "hmac-blake3"

/* ----- Per-case context registry ----------------------------------- */
/*
 * Per-case context registry. Each case's context — encryptor, payload
 * buffer, pristine wire, working buffer, outer key — is allocated
 * through ctx_new() and freed by ctx_free_all() immediately after
 * that case is measured.
 */
typedef struct case_ctx case_ctx_t;
typedef void (*case_cleanup_fn)(case_ctx_t *c);

struct case_ctx {
    /* Per-case cleanup hook — NULL on cases whose context is just a
     * static (payload + key) tuple that does not need teardown. */
    case_cleanup_fn cleanup;
    /* Encryptor handle for cases that bind one. */
    itb_encryptor_t *enc;
    /* Plain ITB payload for the encrypt-direction cases. */
    uint8_t *payload;
    size_t payload_len;
    /* Pristine wire (cipher-XORed, including nonce prefix) used by
     * decrypt-direction cases — the per-iter loop memcpys into a
     * working buffer before unwrapping in place. */
    uint8_t *pristine_wire;
    size_t pristine_wire_len;
    /* Working buffer for the per-iter run: malloc'd once, sized to
     * pristine_wire_len; filled fresh by memcpy at the top of each
     * iter. */
    uint8_t *work_wire;
    /* Per-iter outer cipher key handle. */
    uint8_t *outer_key;
    size_t outer_key_len;
    /* Cipher selector + name (interned). */
    itb_wrapper_cipher_t cipher;
    /* Mode flag: 1 = Single, 3 = Triple. Stored only for diagnostics. */
    int mode;
    /* Auth flag for Message-* cases (1 = use encrypt_auth /
     * decrypt_auth). */
    int auth;
};

static case_ctx_t **g_ctx_registry = NULL;
static size_t g_ctx_registry_len = 0;
static size_t g_ctx_registry_cap = 0;

static case_ctx_t *ctx_new(void)
{
    case_ctx_t *c = (case_ctx_t *) calloc(1, sizeof(*c));
    if (c == NULL) {
        fprintf(stderr, "ctx_new: out of memory\n");
        abort();
    }
    if (g_ctx_registry_len == g_ctx_registry_cap) {
        size_t new_cap = g_ctx_registry_cap == 0 ? 128 : g_ctx_registry_cap * 2;
        case_ctx_t **next =
            (case_ctx_t **) realloc(g_ctx_registry, new_cap * sizeof(*next));
        if (next == NULL) {
            fprintf(stderr, "ctx_new: registry grow failed\n");
            abort();
        }
        g_ctx_registry = next;
        g_ctx_registry_cap = new_cap;
    }
    g_ctx_registry[g_ctx_registry_len++] = c;
    return c;
}

static void default_cleanup(case_ctx_t *c)
{
    if (c->enc != NULL) {
        itb_encryptor_free(c->enc);
        c->enc = NULL;
    }
    free(c->payload);
    c->payload = NULL;
    free(c->pristine_wire);
    c->pristine_wire = NULL;
    free(c->work_wire);
    c->work_wire = NULL;
    if (c->outer_key != NULL) {
        itb_buffer_free(c->outer_key);
        c->outer_key = NULL;
    }
}

static void ctx_free_all(void)
{
    for (size_t i = 0; i < g_ctx_registry_len; i++) {
        case_ctx_t *c = g_ctx_registry[i];
        if (c == NULL) continue;
        if (c->cleanup != NULL) {
            c->cleanup(c);
        } else {
            default_cleanup(c);
        }
        free(c);
    }
    free(g_ctx_registry);
    g_ctx_registry = NULL;
    g_ctx_registry_len = 0;
    g_ctx_registry_cap = 0;
}

/* ----- Encryptor factory ------------------------------------------- */

static itb_encryptor_t *new_encryptor(int mode, int with_mac)
{
    itb_encryptor_t *e = NULL;
    itb_status_t s = itb_encryptor_new(BENCH_PRIMITIVE, BENCH_KEY_BITS,
                                       with_mac ? BENCH_MAC_NAME : "",
                                       mode, &e);
    if (s != ITB_OK || e == NULL) {
        fprintf(stderr, "itb_encryptor_new(mode=%d, mac=%d) failed: %s\n",
                mode, with_mac, itb_last_error());
        abort();
    }
    /* Match the wrapper/bench_test.go config: minimal config so the
     * outer cipher delta is not masked by per-pixel feature cost. */
    if (itb_encryptor_set_nonce_bits(e, 128) != ITB_OK
        || itb_encryptor_set_barrier_fill(e, 1) != ITB_OK
        || itb_encryptor_set_bit_soup(e, 0) != ITB_OK
        || itb_encryptor_set_lock_soup(e, 0) != ITB_OK) {
        fprintf(stderr, "encryptor knob set failed: %s\n", itb_last_error());
        abort();
    }
    return e;
}

/* ----- Wrapper Only sub-benches ----------------------------------- */
/*
 * Pure outer cipher cost — no ITB call. Two variants per cipher:
 * Wrap (alloc) and WrapInPlace (no output-buffer alloc).
 *
 * Each iter performs one wrap + one unwrap (encrypt + decrypt timed
 * together, mirroring the Go BenchmarkWrapperOnlyWrap / InPlace
 * cases). Payload is 16 MiB pseudo-random bytes.
 */

static void run_wrapper_only_wrap(void *ctx, uint64_t iters)
{
    case_ctx_t *c = (case_ctx_t *) ctx;
    for (uint64_t i = 0; i < iters; i++) {
        uint8_t *wire = NULL;
        size_t wire_len = 0;
        if (itb_wrap(c->cipher, c->outer_key, c->outer_key_len,
                     c->payload, c->payload_len, &wire, &wire_len) != ITB_OK) {
            fprintf(stderr, "itb_wrap failed: %s\n", itb_last_error());
            abort();
        }
        uint8_t *recovered = NULL;
        size_t recovered_len = 0;
        if (itb_unwrap(c->cipher, c->outer_key, c->outer_key_len,
                       wire, wire_len, &recovered, &recovered_len) != ITB_OK) {
            fprintf(stderr, "itb_unwrap failed: %s\n", itb_last_error());
            abort();
        }
        itb_buffer_free(wire);
        itb_buffer_free(recovered);
    }
}

static void run_wrapper_only_inplace(void *ctx, uint64_t iters)
{
    case_ctx_t *c = (case_ctx_t *) ctx;
    /* Per-iter: refresh c->work_wire's body region from c->payload,
     * wrap_in_place into the body and write the nonce into the
     * header; then unwrap_in_place over the full wire. */
    size_t nlen = 0;
    if (itb_wrapper_nonce_size(c->cipher, &nlen) != ITB_OK) {
        fprintf(stderr, "nonce_size: %s\n", itb_last_error());
        abort();
    }
    for (uint64_t i = 0; i < iters; i++) {
        memcpy(c->work_wire + nlen, c->payload, c->payload_len);
        if (itb_wrap_in_place(c->cipher, c->outer_key, c->outer_key_len,
                              c->work_wire + nlen, c->payload_len,
                              c->work_wire, nlen) != ITB_OK) {
            fprintf(stderr, "itb_wrap_in_place: %s\n", itb_last_error());
            abort();
        }
        if (itb_unwrap_in_place(c->cipher, c->outer_key, c->outer_key_len,
                                c->work_wire, nlen + c->payload_len) != ITB_OK) {
            fprintf(stderr, "itb_unwrap_in_place: %s\n", itb_last_error());
            abort();
        }
    }
}

static bench_case_t make_wrapper_only_wrap_case(itb_wrapper_cipher_t cipher,
                                                const char *cipher_name)
{
    case_ctx_t *c = ctx_new();
    c->cipher = cipher;
    c->payload = random_bytes_alloc(WRAPPER_PAYLOAD_BYTES);
    if (c->payload == NULL) {
        fprintf(stderr, "wrapper_only payload alloc failed\n");
        abort();
    }
    c->payload_len = WRAPPER_PAYLOAD_BYTES;
    if (itb_wrapper_generate_key(cipher, &c->outer_key, &c->outer_key_len) != ITB_OK) {
        fprintf(stderr, "generate_key: %s\n", itb_last_error());
        abort();
    }
    bench_case_t bc = {
        bench_strdup_fmt("BenchmarkWrapperOnlyWrap/%s", cipher_name),
        run_wrapper_only_wrap, c, WRAPPER_PAYLOAD_BYTES,
    };
    return bc;
}

static bench_case_t make_wrapper_only_inplace_case(itb_wrapper_cipher_t cipher,
                                                   const char *cipher_name)
{
    case_ctx_t *c = ctx_new();
    c->cipher = cipher;
    c->payload = random_bytes_alloc(WRAPPER_PAYLOAD_BYTES);
    if (c->payload == NULL) {
        fprintf(stderr, "wrapper_only payload alloc failed\n");
        abort();
    }
    c->payload_len = WRAPPER_PAYLOAD_BYTES;
    if (itb_wrapper_generate_key(cipher, &c->outer_key, &c->outer_key_len) != ITB_OK) {
        fprintf(stderr, "generate_key: %s\n", itb_last_error());
        abort();
    }
    size_t nlen = 0;
    (void) itb_wrapper_nonce_size(cipher, &nlen);
    c->work_wire = (uint8_t *) malloc(nlen + WRAPPER_PAYLOAD_BYTES);
    if (c->work_wire == NULL) {
        fprintf(stderr, "wrapper_only work_wire alloc failed\n");
        abort();
    }
    bench_case_t bc = {
        bench_strdup_fmt("BenchmarkWrapperOnlyInPlace/%s", cipher_name),
        run_wrapper_only_inplace, c, WRAPPER_PAYLOAD_BYTES,
    };
    return bc;
}

/* ----- Message benches --------------------------------------------- */
/*
 * Encrypt and decrypt timed separately. The encrypt path ITB-encrypts
 * the payload then wraps the ciphertext blob; decrypt unwraps the
 * pristine wire (memcpy'd in fresh per iter) then ITB-decrypts.
 *
 * Per-iter on encrypt: encryptor_encrypt -> itb_wrap -> free both
 *   buffers. Allocation cost is part of the steady-state ratio the
 *   numbers report.
 * Per-iter on decrypt: memcpy work_wire <- pristine_wire -> unwrap
 *   into a freshly malloc'd recovered -> encryptor_decrypt over the
 *   recovered bytes -> free recovered + decrypted-pt.
 */

static void run_message_encrypt(void *ctx, uint64_t iters)
{
    case_ctx_t *c = (case_ctx_t *) ctx;
    for (uint64_t i = 0; i < iters; i++) {
        uint8_t *ct = NULL;
        size_t ct_len = 0;
        itb_status_t s = c->auth
            ? itb_encryptor_encrypt_auth(c->enc, c->payload, c->payload_len, &ct, &ct_len)
            : itb_encryptor_encrypt(c->enc, c->payload, c->payload_len, &ct, &ct_len);
        if (s != ITB_OK) {
            fprintf(stderr, "encryptor_encrypt: %s\n", itb_last_error());
            abort();
        }
        uint8_t *wire = NULL;
        size_t wire_len = 0;
        if (itb_wrap(c->cipher, c->outer_key, c->outer_key_len,
                     ct, ct_len, &wire, &wire_len) != ITB_OK) {
            fprintf(stderr, "itb_wrap: %s\n", itb_last_error());
            abort();
        }
        itb_buffer_free(ct);
        itb_buffer_free(wire);
    }
}

static void run_message_decrypt(void *ctx, uint64_t iters)
{
    case_ctx_t *c = (case_ctx_t *) ctx;
    for (uint64_t i = 0; i < iters; i++) {
        memcpy(c->work_wire, c->pristine_wire, c->pristine_wire_len);
        uint8_t *recovered = NULL;
        size_t recovered_len = 0;
        if (itb_unwrap(c->cipher, c->outer_key, c->outer_key_len,
                       c->work_wire, c->pristine_wire_len,
                       &recovered, &recovered_len) != ITB_OK) {
            fprintf(stderr, "itb_unwrap: %s\n", itb_last_error());
            abort();
        }
        uint8_t *pt = NULL;
        size_t pt_len = 0;
        itb_status_t s = c->auth
            ? itb_encryptor_decrypt_auth(c->enc, recovered, recovered_len, &pt, &pt_len)
            : itb_encryptor_decrypt(c->enc, recovered, recovered_len, &pt, &pt_len);
        if (s != ITB_OK) {
            fprintf(stderr, "encryptor_decrypt: %s\n", itb_last_error());
            abort();
        }
        itb_buffer_free(recovered);
        itb_buffer_free(pt);
    }
}

static bench_case_t make_message_encrypt_case(int mode, int auth,
                                              itb_wrapper_cipher_t cipher,
                                              const char *cipher_name,
                                              const char *label)
{
    case_ctx_t *c = ctx_new();
    c->mode = mode;
    c->auth = auth;
    c->cipher = cipher;
    c->enc = new_encryptor(mode, auth);
    c->payload = random_bytes_alloc(MESSAGE_PAYLOAD_BYTES);
    if (c->payload == NULL) {
        fprintf(stderr, "message payload alloc failed\n");
        abort();
    }
    c->payload_len = MESSAGE_PAYLOAD_BYTES;
    if (itb_wrapper_generate_key(cipher, &c->outer_key, &c->outer_key_len) != ITB_OK) {
        fprintf(stderr, "generate_key: %s\n", itb_last_error());
        abort();
    }
    const char *mode_name = (mode == 1) ? "Single" : "Triple";
    bench_case_t bc = {
        bench_strdup_fmt("BenchmarkMessage%s/%s/%s/encrypt",
                         mode_name, label, cipher_name),
        run_message_encrypt, c, MESSAGE_PAYLOAD_BYTES,
    };
    return bc;
}

static bench_case_t make_message_decrypt_case(int mode, int auth,
                                              itb_wrapper_cipher_t cipher,
                                              const char *cipher_name,
                                              const char *label)
{
    case_ctx_t *c = ctx_new();
    c->mode = mode;
    c->auth = auth;
    c->cipher = cipher;
    c->enc = new_encryptor(mode, auth);
    c->payload = random_bytes_alloc(MESSAGE_PAYLOAD_BYTES);
    if (c->payload == NULL) {
        fprintf(stderr, "message payload alloc failed\n");
        abort();
    }
    c->payload_len = MESSAGE_PAYLOAD_BYTES;
    if (itb_wrapper_generate_key(cipher, &c->outer_key, &c->outer_key_len) != ITB_OK) {
        fprintf(stderr, "generate_key: %s\n", itb_last_error());
        abort();
    }
    /* Build pristine wire = wrap(encrypt(payload)). */
    uint8_t *ct = NULL;
    size_t ct_len = 0;
    itb_status_t s = auth
        ? itb_encryptor_encrypt_auth(c->enc, c->payload, c->payload_len, &ct, &ct_len)
        : itb_encryptor_encrypt(c->enc, c->payload, c->payload_len, &ct, &ct_len);
    if (s != ITB_OK) {
        fprintf(stderr, "priming encrypt: %s\n", itb_last_error());
        abort();
    }
    if (itb_wrap(c->cipher, c->outer_key, c->outer_key_len,
                 ct, ct_len, &c->pristine_wire, &c->pristine_wire_len) != ITB_OK) {
        fprintf(stderr, "priming wrap: %s\n", itb_last_error());
        abort();
    }
    itb_buffer_free(ct);
    c->work_wire = (uint8_t *) malloc(c->pristine_wire_len);
    if (c->work_wire == NULL) {
        fprintf(stderr, "work_wire alloc failed\n");
        abort();
    }
    const char *mode_name = (mode == 1) ? "Single" : "Triple";
    bench_case_t bc = {
        bench_strdup_fmt("BenchmarkMessage%s/%s/%s/decrypt",
                         mode_name, label, cipher_name),
        run_message_decrypt, c, MESSAGE_PAYLOAD_BYTES,
    };
    return bc;
}

/* ----- Streaming benches ------------------------------------------- */
/*
 * 4 modes × 3 ciphers × 2 directions × {Single, Triple} = 48 cases.
 * The C binding's stream APIs take callback pairs; the bench harness
 * uses an in-memory growable sink for the encrypted bytestream.
 *
 * Encrypt direction: ITB stream-encrypt the payload to a memory sink,
 *   then wrap-stream the entire bytestream end-to-end through one
 *   keystream session. (All four streaming modes follow the same
 *   shape — only the inner ITB call differs.)
 *
 * Decrypt direction: memcpy the pristine wire into a working buffer,
 *   strip the leading nonce, unwrap-stream into a fresh inner-bytes
 *   buffer, then ITB stream-decrypt the inner bytes into a sink.
 */

typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
} grow_t;

static int grow_write(void *ctx, const void *buf, size_t n)
{
    grow_t *g = (grow_t *) ctx;
    if (g->len + n > g->cap) {
        size_t new_cap = g->cap == 0 ? 4096 : g->cap * 2;
        while (new_cap < g->len + n) new_cap *= 2;
        uint8_t *p = (uint8_t *) realloc(g->data, new_cap);
        if (p == NULL) return 1;
        g->data = p;
        g->cap = new_cap;
    }
    memcpy(g->data + g->len, buf, n);
    g->len += n;
    return 0;
}

typedef struct {
    const uint8_t *data;
    size_t len;
    size_t pos;
} mread_t;

static int mread_read(void *ctx, void *buf, size_t cap, size_t *out_n)
{
    mread_t *m = (mread_t *) ctx;
    size_t avail = m->len - m->pos;
    size_t want = (cap < avail) ? cap : avail;
    if (want > 0) {
        memcpy(buf, m->data + m->pos, want);
        m->pos += want;
    }
    *out_n = want;
    return 0;
}

/* Streaming context — owns the encryptor, payload, pristine_wire,
 * and one work buffer reused per iter. The mode label decides which
 * inner ITB stream call gets invoked. */
typedef enum {
    STREAM_AEAD_EASY_IO,
    STREAM_AEAD_LOWLEVEL_IO,
    STREAM_NOAEAD_EASY_USERLOOP,
    STREAM_NOAEAD_LOWLEVEL_USERLOOP,
} stream_mode_t;

typedef struct {
    case_ctx_t base; /* Aliased — bench_case_t passes &base as ctx. */
} stream_ctx_t;

/* Inner ITB encrypt for the AEAD-Easy / AEAD-Low-Level streaming
 * modes; the User-Driven Loop modes have their own inner shape. */
static void encrypt_aead_easy_inner(case_ctx_t *c, grow_t *out)
{
    mread_t src = { c->payload, c->payload_len, 0 };
    if (itb_encryptor_stream_encrypt_auth(c->enc, mread_read, &src,
                                          grow_write, out,
                                          STREAM_CHUNK_BYTES) != ITB_OK) {
        fprintf(stderr, "stream_encrypt_auth: %s\n", itb_last_error());
        abort();
    }
}

static void decrypt_aead_easy_inner(case_ctx_t *c,
                                    const uint8_t *inner, size_t inner_len,
                                    grow_t *pt_out)
{
    mread_t src = { inner, inner_len, 0 };
    if (itb_encryptor_stream_decrypt_auth(c->enc, mread_read, &src,
                                          grow_write, pt_out,
                                          STREAM_CHUNK_BYTES) != ITB_OK) {
        fprintf(stderr, "stream_decrypt_auth: %s\n", itb_last_error());
        abort();
    }
}

/* User-Driven Loop encrypt: for each chunk, encrypt to ITB CT then
 * emit a u32_LE length prefix + body through the wrap-writer; both
 * pass through the keystream XOR. */
static void put_u32_le(uint8_t *dst, uint32_t v)
{
    dst[0] = (uint8_t) (v & 0xFFu);
    dst[1] = (uint8_t) ((v >> 8) & 0xFFu);
    dst[2] = (uint8_t) ((v >> 16) & 0xFFu);
    dst[3] = (uint8_t) ((v >> 24) & 0xFFu);
}

static uint32_t get_u32_le(const uint8_t *src)
{
    return (uint32_t) src[0]
         | ((uint32_t) src[1] << 8)
         | ((uint32_t) src[2] << 16)
         | ((uint32_t) src[3] << 24);
}

static void encrypt_userloop_inner(case_ctx_t *c, grow_t *wire_out,
                                   itb_wrap_stream_writer_t *ww)
{
    /* Iterates the payload by STREAM_CHUNK_BYTES; per-chunk emits
     * (u32_LE_len || ct) through the wrap-writer. The wire_out
     * accumulates the post-XOR bytes; the caller has already written
     * the nonce prefix. */
    for (size_t off = 0; off < c->payload_len; off += STREAM_CHUNK_BYTES) {
        size_t take = c->payload_len - off;
        if (take > STREAM_CHUNK_BYTES) take = STREAM_CHUNK_BYTES;
        uint8_t *ct = NULL;
        size_t ct_len = 0;
        if (itb_encryptor_encrypt(c->enc, c->payload + off, take, &ct, &ct_len) != ITB_OK) {
            fprintf(stderr, "encryptor_encrypt: %s\n", itb_last_error());
            abort();
        }
        uint8_t hdr[4];
        put_u32_le(hdr, (uint32_t) ct_len);
        uint8_t hdr_xor[4];
        if (itb_wrap_stream_writer_update(ww, hdr, 4, hdr_xor, 4) != ITB_OK) {
            fprintf(stderr, "wrap update hdr: %s\n", itb_last_error());
            abort();
        }
        if (grow_write(wire_out, hdr_xor, 4) != 0) abort();
        uint8_t *ct_xor = (uint8_t *) malloc(ct_len);
        if (ct_xor == NULL) abort();
        if (itb_wrap_stream_writer_update(ww, ct, ct_len, ct_xor, ct_len) != ITB_OK) {
            fprintf(stderr, "wrap update ct: %s\n", itb_last_error());
            abort();
        }
        if (grow_write(wire_out, ct_xor, ct_len) != 0) abort();
        free(ct_xor);
        itb_buffer_free(ct);
    }
}

static void decrypt_userloop_inner(case_ctx_t *c,
                                   itb_unwrap_stream_reader_t *ur,
                                   const uint8_t *body, size_t body_len,
                                   grow_t *pt_out)
{
    size_t off = 0;
    while (off < body_len) {
        if (off + 4 > body_len) abort();
        uint8_t hdr[4];
        if (itb_unwrap_stream_reader_update(ur, body + off, 4, hdr, 4) != ITB_OK) abort();
        off += 4;
        uint32_t clen = get_u32_le(hdr);
        if (off + clen > body_len) abort();
        uint8_t *ct = (uint8_t *) malloc(clen);
        if (ct == NULL) abort();
        if (itb_unwrap_stream_reader_update(ur, body + off, clen, ct, clen) != ITB_OK) abort();
        off += clen;
        uint8_t *pt = NULL;
        size_t pt_len = 0;
        if (itb_encryptor_decrypt(c->enc, ct, clen, &pt, &pt_len) != ITB_OK) abort();
        free(ct);
        if (grow_write(pt_out, pt, pt_len) != 0) abort();
        itb_buffer_free(pt);
    }
}

/* Per-iter run for AEAD streaming encrypt (mode 0 / 1 ↔
 * STREAM_AEAD_*_IO). The inner Easy / Low-Level distinction is
 * subsumed: both call itb_encryptor_stream_encrypt_auth in the C
 * binding via the encryptor handle, so the encryptor's mode (Single
 * / Triple) is the only knob the bench varies. */
static void run_stream_aead_encrypt(void *ctx, uint64_t iters)
{
    case_ctx_t *c = (case_ctx_t *) ctx;
    for (uint64_t i = 0; i < iters; i++) {
        grow_t inner = {0};
        encrypt_aead_easy_inner(c, &inner);

        size_t nlen = 0;
        (void) itb_wrapper_nonce_size(c->cipher, &nlen);
        uint8_t nonce_buf[16];
        itb_wrap_stream_writer_t *ww = NULL;
        if (itb_wrap_stream_writer_new(c->cipher, c->outer_key, c->outer_key_len,
                                       nonce_buf, sizeof(nonce_buf), &ww) != ITB_OK) {
            fprintf(stderr, "wrap_stream_writer_new: %s\n", itb_last_error());
            abort();
        }
        uint8_t *body_xor = (uint8_t *) malloc(inner.len);
        if (body_xor == NULL) abort();
        if (itb_wrap_stream_writer_update(ww, inner.data, inner.len,
                                          body_xor, inner.len) != ITB_OK) abort();
        itb_wrap_stream_writer_free(ww);
        free(body_xor);
        free(inner.data);
    }
}

static void run_stream_aead_decrypt(void *ctx, uint64_t iters)
{
    case_ctx_t *c = (case_ctx_t *) ctx;
    size_t nlen = 0;
    (void) itb_wrapper_nonce_size(c->cipher, &nlen);
    for (uint64_t i = 0; i < iters; i++) {
        memcpy(c->work_wire, c->pristine_wire, c->pristine_wire_len);
        itb_unwrap_stream_reader_t *ur = NULL;
        if (itb_unwrap_stream_reader_new(c->cipher, c->outer_key, c->outer_key_len,
                                         c->work_wire, nlen, &ur) != ITB_OK) {
            fprintf(stderr, "unwrap_stream_reader_new: %s\n", itb_last_error());
            abort();
        }
        size_t body_len = c->pristine_wire_len - nlen;
        uint8_t *inner = (uint8_t *) malloc(body_len);
        if (inner == NULL) abort();
        if (itb_unwrap_stream_reader_update(ur, c->work_wire + nlen, body_len,
                                            inner, body_len) != ITB_OK) abort();
        itb_unwrap_stream_reader_free(ur);

        grow_t pt_out = {0};
        decrypt_aead_easy_inner(c, inner, body_len, &pt_out);
        free(inner);
        free(pt_out.data);
    }
}

static void run_stream_userloop_encrypt(void *ctx, uint64_t iters)
{
    case_ctx_t *c = (case_ctx_t *) ctx;
    size_t nlen = 0;
    (void) itb_wrapper_nonce_size(c->cipher, &nlen);
    for (uint64_t i = 0; i < iters; i++) {
        grow_t wire_out = {0};
        uint8_t nonce_buf[16];
        itb_wrap_stream_writer_t *ww = NULL;
        if (itb_wrap_stream_writer_new(c->cipher, c->outer_key, c->outer_key_len,
                                       nonce_buf, sizeof(nonce_buf), &ww) != ITB_OK) abort();
        if (grow_write(&wire_out, nonce_buf, nlen) != 0) abort();
        encrypt_userloop_inner(c, &wire_out, ww);
        itb_wrap_stream_writer_free(ww);
        free(wire_out.data);
    }
}

static void run_stream_userloop_decrypt(void *ctx, uint64_t iters)
{
    case_ctx_t *c = (case_ctx_t *) ctx;
    size_t nlen = 0;
    (void) itb_wrapper_nonce_size(c->cipher, &nlen);
    for (uint64_t i = 0; i < iters; i++) {
        memcpy(c->work_wire, c->pristine_wire, c->pristine_wire_len);
        itb_unwrap_stream_reader_t *ur = NULL;
        if (itb_unwrap_stream_reader_new(c->cipher, c->outer_key, c->outer_key_len,
                                         c->work_wire, nlen, &ur) != ITB_OK) abort();
        grow_t pt_out = {0};
        decrypt_userloop_inner(c, ur,
                               c->work_wire + nlen,
                               c->pristine_wire_len - nlen, &pt_out);
        itb_unwrap_stream_reader_free(ur);
        free(pt_out.data);
    }
}

/* Build a stream encrypt sub-bench. `mode` is 1/3 (Single/Triple),
 * `auth` is 1 for the AEAD modes / 0 for the No MAC userloop modes,
 * `kind` selects the run_fn. */
static bench_case_t make_stream_encrypt_case(int mode, int auth,
                                             stream_mode_t kind,
                                             itb_wrapper_cipher_t cipher,
                                             const char *cipher_name,
                                             const char *label)
{
    case_ctx_t *c = ctx_new();
    c->mode = mode;
    c->auth = auth;
    c->cipher = cipher;
    c->enc = new_encryptor(mode, auth);
    c->payload = random_bytes_alloc(STREAM_PAYLOAD_BYTES);
    if (c->payload == NULL) {
        fprintf(stderr, "stream payload alloc failed\n");
        abort();
    }
    c->payload_len = STREAM_PAYLOAD_BYTES;
    if (itb_wrapper_generate_key(cipher, &c->outer_key, &c->outer_key_len) != ITB_OK) {
        fprintf(stderr, "generate_key: %s\n", itb_last_error());
        abort();
    }

    bench_run_fn run = NULL;
    switch (kind) {
    case STREAM_AEAD_EASY_IO:
    case STREAM_AEAD_LOWLEVEL_IO:
        run = run_stream_aead_encrypt;
        break;
    case STREAM_NOAEAD_EASY_USERLOOP:
    case STREAM_NOAEAD_LOWLEVEL_USERLOOP:
        run = run_stream_userloop_encrypt;
        break;
    }
    const char *mode_name = (mode == 1) ? "Single" : "Triple";
    bench_case_t bc = {
        bench_strdup_fmt("BenchmarkStreaming%s/%s/%s/encrypt",
                         mode_name, label, cipher_name),
        run, c, STREAM_PAYLOAD_BYTES,
    };
    return bc;
}

/* Per-iter decrypt requires a pristine wire — encrypt + wrap once at
 * setup, memcpy fresh per iter. */
static void prime_pristine_aead(case_ctx_t *c)
{
    grow_t inner = {0};
    encrypt_aead_easy_inner(c, &inner);
    size_t nlen = 0;
    (void) itb_wrapper_nonce_size(c->cipher, &nlen);
    uint8_t nonce_buf[16];
    itb_wrap_stream_writer_t *ww = NULL;
    if (itb_wrap_stream_writer_new(c->cipher, c->outer_key, c->outer_key_len,
                                   nonce_buf, sizeof(nonce_buf), &ww) != ITB_OK) abort();
    c->pristine_wire_len = nlen + inner.len;
    c->pristine_wire = (uint8_t *) malloc(c->pristine_wire_len);
    if (c->pristine_wire == NULL) abort();
    memcpy(c->pristine_wire, nonce_buf, nlen);
    if (itb_wrap_stream_writer_update(ww, inner.data, inner.len,
                                      c->pristine_wire + nlen, inner.len) != ITB_OK) abort();
    itb_wrap_stream_writer_free(ww);
    free(inner.data);
    c->work_wire = (uint8_t *) malloc(c->pristine_wire_len);
    if (c->work_wire == NULL) abort();
}

static void prime_pristine_userloop(case_ctx_t *c)
{
    grow_t wire_out = {0};
    size_t nlen = 0;
    (void) itb_wrapper_nonce_size(c->cipher, &nlen);
    uint8_t nonce_buf[16];
    itb_wrap_stream_writer_t *ww = NULL;
    if (itb_wrap_stream_writer_new(c->cipher, c->outer_key, c->outer_key_len,
                                   nonce_buf, sizeof(nonce_buf), &ww) != ITB_OK) abort();
    if (grow_write(&wire_out, nonce_buf, nlen) != 0) abort();
    encrypt_userloop_inner(c, &wire_out, ww);
    itb_wrap_stream_writer_free(ww);
    c->pristine_wire = wire_out.data;
    c->pristine_wire_len = wire_out.len;
    c->work_wire = (uint8_t *) malloc(c->pristine_wire_len);
    if (c->work_wire == NULL) abort();
}

static bench_case_t make_stream_decrypt_case(int mode, int auth,
                                             stream_mode_t kind,
                                             itb_wrapper_cipher_t cipher,
                                             const char *cipher_name,
                                             const char *label)
{
    case_ctx_t *c = ctx_new();
    c->mode = mode;
    c->auth = auth;
    c->cipher = cipher;
    c->enc = new_encryptor(mode, auth);
    c->payload = random_bytes_alloc(STREAM_PAYLOAD_BYTES);
    if (c->payload == NULL) abort();
    c->payload_len = STREAM_PAYLOAD_BYTES;
    if (itb_wrapper_generate_key(cipher, &c->outer_key, &c->outer_key_len) != ITB_OK) abort();

    bench_run_fn run = NULL;
    switch (kind) {
    case STREAM_AEAD_EASY_IO:
    case STREAM_AEAD_LOWLEVEL_IO:
        prime_pristine_aead(c);
        run = run_stream_aead_decrypt;
        break;
    case STREAM_NOAEAD_EASY_USERLOOP:
    case STREAM_NOAEAD_LOWLEVEL_USERLOOP:
        prime_pristine_userloop(c);
        run = run_stream_userloop_decrypt;
        break;
    }
    const char *mode_name = (mode == 1) ? "Single" : "Triple";
    bench_case_t bc = {
        bench_strdup_fmt("BenchmarkStreaming%s/%s/%s/decrypt",
                         mode_name, label, cipher_name),
        run, c, STREAM_PAYLOAD_BYTES,
    };
    return bc;
}

/* ----- Lazy descriptor --------------------------------------------- */

/* One lazy descriptor: label strings (interned literals + cipher index)
 * so the name can be reconstructed without holding heap memory, plus the
 * knobs needed to call the right make_* factory.  Building all 306
 * descriptors is O(1) in payload memory; each factory is invoked just
 * before timing and its context freed immediately after. */

/* Case kind selector. */
#define KIND_WRAP_WRAP    0
#define KIND_WRAP_INPLACE 1
#define KIND_MSG_ENC      2
#define KIND_MSG_DEC      3
#define KIND_STR_ENC      4
#define KIND_STR_DEC      5

typedef struct {
    int             kind;
    int             ci;       /* CIPHERS / CIPHER_NAMES index */
    int             mode;     /* 1=Single, 3=Triple (msg/stream only) */
    int             auth;     /* 0=NoMAC, 1=Auth (msg/stream only) */
    stream_mode_t   stream_k; /* stream kind (stream only) */
    const char     *label;    /* interned literal, e.g. "easy-nomac" */
} lazy_desc_t;

/* ----- Total factory count ----------------------------------------- */
/* 2 wrapper-only + 16 message + 16 streaming = 34 per cipher; ×9 = 306. */
#define TOTAL_CASES (34 * CIPHER_COUNT)

int main(void)
{
    int nonce_bits = env_nonce_bits(128);
    if (itb_set_max_workers(0) != ITB_OK) {
        fprintf(stderr, "itb_set_max_workers(0) failed: %s\n", itb_last_error());
        return 1;
    }
    if (itb_set_nonce_bits(nonce_bits) != ITB_OK) {
        fprintf(stderr, "itb_set_nonce_bits(%d) failed: %s\n",
                nonce_bits, itb_last_error());
        return 1;
    }

    /* ----- Build cheap descriptor list (no payload allocs) ---------- */

    static const struct { const char *label; int auth; } MSG_LABELS[] = {
        { "easy-nomac",      0 },
        { "easy-auth",       1 },
        { "lowlevel-nomac",  0 },
        { "lowlevel-auth",   1 },
    };
    static const struct { const char *label; stream_mode_t kind; int auth; }
    STREAM_LABELS[] = {
        { "aead-easy-io",             STREAM_AEAD_EASY_IO,             1 },
        { "aead-lowlevel-io",         STREAM_AEAD_LOWLEVEL_IO,         1 },
        { "noaead-easy-userloop",     STREAM_NOAEAD_EASY_USERLOOP,     0 },
        { "noaead-lowlevel-userloop", STREAM_NOAEAD_LOWLEVEL_USERLOOP, 0 },
    };
    static const int MODES[] = { 1, 3 };

    lazy_desc_t *descs =
        (lazy_desc_t *) calloc(TOTAL_CASES, sizeof(lazy_desc_t));
    if (descs == NULL) {
        fprintf(stderr, "descriptor alloc failed\n");
        return 1;
    }
    size_t n_descs = 0;

    /* Wrapper Only — 2 per cipher. */
    for (int ci = 0; ci < CIPHER_COUNT; ci++) {
        descs[n_descs++] = (lazy_desc_t){ KIND_WRAP_WRAP,    ci, 0, 0, 0, NULL };
        descs[n_descs++] = (lazy_desc_t){ KIND_WRAP_INPLACE, ci, 0, 0, 0, NULL };
    }

    /* Message — 2 ouroboros × 4 labels × every cipher × 2 dirs. */
    for (size_t mi = 0; mi < sizeof(MODES)/sizeof(MODES[0]); mi++) {
        int mode = MODES[mi];
        for (size_t li = 0; li < sizeof(MSG_LABELS)/sizeof(MSG_LABELS[0]); li++) {
            for (int ci = 0; ci < CIPHER_COUNT; ci++) {
                descs[n_descs++] = (lazy_desc_t){
                    KIND_MSG_ENC, ci, mode, MSG_LABELS[li].auth, 0, MSG_LABELS[li].label
                };
                descs[n_descs++] = (lazy_desc_t){
                    KIND_MSG_DEC, ci, mode, MSG_LABELS[li].auth, 0, MSG_LABELS[li].label
                };
            }
        }
    }

    /* Streaming — 2 ouroboros × 4 labels × every cipher × 2 dirs. */
    for (size_t mi = 0; mi < sizeof(MODES)/sizeof(MODES[0]); mi++) {
        int mode = MODES[mi];
        for (size_t li = 0; li < sizeof(STREAM_LABELS)/sizeof(STREAM_LABELS[0]); li++) {
            for (int ci = 0; ci < CIPHER_COUNT; ci++) {
                descs[n_descs++] = (lazy_desc_t){
                    KIND_STR_ENC, ci, mode, STREAM_LABELS[li].auth,
                    STREAM_LABELS[li].kind, STREAM_LABELS[li].label
                };
                descs[n_descs++] = (lazy_desc_t){
                    KIND_STR_DEC, ci, mode, STREAM_LABELS[li].auth,
                    STREAM_LABELS[li].kind, STREAM_LABELS[li].label
                };
            }
        }
    }

    if (n_descs != TOTAL_CASES) {
        fprintf(stderr, "descriptor build yielded %zu, expected %d\n",
                n_descs, TOTAL_CASES);
        free(descs);
        return 1;
    }

    /* ----- Filter + count ------------------------------------------- */

    const char *flt = env_filter();
    double min_seconds = env_min_seconds();

    /* Build a temporary name for each descriptor to evaluate the filter.
     * We keep only the selected indices (no heap-owned name yet). */
    size_t *sel_idx = (size_t *) malloc(n_descs * sizeof(size_t));
    if (sel_idx == NULL) {
        fprintf(stderr, "sel_idx alloc failed\n");
        free(descs);
        return 1;
    }
    size_t n_sel = 0;
    for (size_t i = 0; i < n_descs; i++) {
        lazy_desc_t *d = &descs[i];
        const char *mode_name = (d->mode == 1 || d->mode == 0) ? "Single" : "Triple";
        char tmp[256];
        switch (d->kind) {
        case KIND_WRAP_WRAP:
            snprintf(tmp, sizeof(tmp), "BenchmarkWrapperOnlyWrap/%s", CIPHER_NAMES[d->ci]);
            break;
        case KIND_WRAP_INPLACE:
            snprintf(tmp, sizeof(tmp), "BenchmarkWrapperOnlyInPlace/%s", CIPHER_NAMES[d->ci]);
            break;
        case KIND_MSG_ENC:
            snprintf(tmp, sizeof(tmp), "BenchmarkMessage%s/%s/%s/encrypt",
                     mode_name, d->label, CIPHER_NAMES[d->ci]);
            break;
        case KIND_MSG_DEC:
            snprintf(tmp, sizeof(tmp), "BenchmarkMessage%s/%s/%s/decrypt",
                     mode_name, d->label, CIPHER_NAMES[d->ci]);
            break;
        case KIND_STR_ENC:
            snprintf(tmp, sizeof(tmp), "BenchmarkStreaming%s/%s/%s/encrypt",
                     mode_name, d->label, CIPHER_NAMES[d->ci]);
            break;
        case KIND_STR_DEC:
            snprintf(tmp, sizeof(tmp), "BenchmarkStreaming%s/%s/%s/decrypt",
                     mode_name, d->label, CIPHER_NAMES[d->ci]);
            break;
        default:
            tmp[0] = '\0';
        }
        if (flt == NULL || strstr(tmp, flt) != NULL)
            sel_idx[n_sel++] = i;
    }

    if (n_sel == 0) {
        fprintf(stderr, "no bench cases match filter %s\n",
                flt == NULL ? "<unset>" : flt);
        free(sel_idx);
        free(descs);
        return 0;
    }

    printf("# wrapper bench primitive=%s key_bits=%d mac=%s "
           "ciphers=%d cases=%zu nonce_bits=%d workers=auto\n",
           BENCH_PRIMITIVE, BENCH_KEY_BITS, BENCH_MAC_NAME,
           CIPHER_COUNT, n_descs, nonce_bits);
    printf("# benchmarks=%zu payload_bytes=%zu min_seconds=%g\n",
           n_sel, (size_t) MESSAGE_PAYLOAD_BYTES, min_seconds);
    fflush(stdout);

    /* ----- Lazy measure loop --------------------------------------- */
    for (size_t s = 0; s < n_sel; s++) {
        lazy_desc_t *d = &descs[sel_idx[s]];
        bench_case_t bc;

        switch (d->kind) {
        case KIND_WRAP_WRAP:
            bc = make_wrapper_only_wrap_case(CIPHERS[d->ci], CIPHER_NAMES[d->ci]);
            break;
        case KIND_WRAP_INPLACE:
            bc = make_wrapper_only_inplace_case(CIPHERS[d->ci], CIPHER_NAMES[d->ci]);
            break;
        case KIND_MSG_ENC:
            bc = make_message_encrypt_case(d->mode, d->auth,
                     CIPHERS[d->ci], CIPHER_NAMES[d->ci], d->label);
            break;
        case KIND_MSG_DEC:
            bc = make_message_decrypt_case(d->mode, d->auth,
                     CIPHERS[d->ci], CIPHER_NAMES[d->ci], d->label);
            break;
        case KIND_STR_ENC:
            bc = make_stream_encrypt_case(d->mode, d->auth, d->stream_k,
                     CIPHERS[d->ci], CIPHER_NAMES[d->ci], d->label);
            break;
        case KIND_STR_DEC:
            bc = make_stream_decrypt_case(d->mode, d->auth, d->stream_k,
                     CIPHERS[d->ci], CIPHER_NAMES[d->ci], d->label);
            break;
        default:
            fprintf(stderr, "unknown kind %d\n", d->kind);
            continue;
        }

        bench_measure_one(&bc, min_seconds);
        free(bc.name);
        bc.name = NULL;
        ctx_free_all(); /* release encryptor / payload / wire for this case */
    }

    free(sel_idx);
    free(descs);
    return 0;
}
