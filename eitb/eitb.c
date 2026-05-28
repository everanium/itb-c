/*
 * eitb.c — wrapper × ITB matrix runner for the C binding.
 *
 * Mirrors tools/eitb/main.go in the root repository, adapted for the C
 * binding's asymmetry: there is no Streaming No MAC IO-Driven example
 * (`noaead-easy-io` / `noaead-lowlevel-io` from the Go matrix) because
 * the C binding does not expose a FILE* / file-like wrapper writer
 * pair for Non-AEAD streaming. The Non-AEAD streaming arm is the
 * User-Driven Loop only.
 *
 * Matrix: 8 examples × outer ciphers.
 *
 * Examples covered:
 *
 *   - aead-easy-io               Streaming AEAD Easy   (MAC Authenticated, IO-Driven)
 *   - aead-lowlevel-io           Streaming AEAD Low-Level (MAC Authenticated, IO-Driven)
 *   - noaead-easy-userloop       Streaming Easy        (No MAC, User-Driven Loop)
 *   - noaead-lowlevel-userloop   Streaming Low-Level   (No MAC, User-Driven Loop)
 *   - message-easy-nomac         Easy Single Message      (No MAC)
 *   - message-easy-auth          Easy Single Message      (MAC Authenticated)
 *   - message-lowlevel-nomac     Low-Level Single Message (No MAC)
 *   - message-lowlevel-auth      Low-Level Single Message (MAC Authenticated)
 *
 * Single-message examples encrypt 1024 bytes; streaming examples
 * encrypt 64 KiB through 16 KiB chunks. Each example runs sender +
 * receiver in the same process, wraps the ITB ciphertext under the
 * chosen outer cipher, hands the wrapped bytes to the receiver path,
 * and verifies sha256 byte-equality of the recovered plaintext
 * against the original.
 *
 * Usage:
 *
 *     ./bin/eitb
 *     ./bin/eitb --example aead
 *     ./bin/eitb --cipher aes
 *     ./bin/eitb -v
 */
#define _POSIX_C_SOURCE 200809L

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "itb.h"

#include "sha256.h"

#define SINGLE_MESSAGE_BYTES 1024u
#define STREAM_BYTES         (64u * 1024u)
#define STREAM_CHUNK_SIZE    (16u * 1024u)

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/* Cipher list in the canonical project primitive order; matches
 * wrapper.CipherNames in the Go-side wrapper package. */
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
#define CIPHER_COUNT (sizeof(CIPHERS) / sizeof(CIPHERS[0]))

static void hex_short(const uint8_t *digest, char *out_hex)
{
    /* First 8 bytes of the digest as 16 hex chars + NUL. */
    static const char hex_chars[] = "0123456789abcdef";
    for (int i = 0; i < 8; i++) {
        out_hex[2 * i + 0] = hex_chars[(digest[i] >> 4) & 0xFu];
        out_hex[2 * i + 1] = hex_chars[digest[i] & 0xFu];
    }
    out_hex[16] = '\0';
}

static int read_csprng(uint8_t *buf, size_t n)
{
    FILE *fp = fopen("/dev/urandom", "rb");
    if (fp == NULL) {
        return -1;
    }
    size_t got = fread(buf, 1, n, fp);
    fclose(fp);
    return got == n ? 0 : -1;
}

/* In-memory growable buffer used as a sink for the AEAD stream
 * encoder. The C binding's stream callback API drives writes in
 * push-mode; this collector accumulates the bytes for downstream
 * wrapping. */
typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} grow_t;

static int grow_write(void *ctx, const void *buf, size_t n)
{
    grow_t *g = (grow_t *) ctx;
    if (g->len + n > g->cap) {
        size_t new_cap = g->cap == 0 ? 4096 : g->cap * 2;
        while (new_cap < g->len + n) {
            new_cap *= 2;
        }
        uint8_t *p = (uint8_t *) realloc(g->data, new_cap);
        if (p == NULL) {
            return 1;
        }
        g->data = p;
        g->cap = new_cap;
    }
    memcpy(g->data + g->len, buf, n);
    g->len += n;
    return 0;
}

/* In-memory read source for the stream callback API. */
typedef struct {
    const uint8_t *data;
    size_t         len;
    size_t         pos;
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

/* ------------------------------------------------------------------ */
/* Per-example results                                                  */
/* ------------------------------------------------------------------ */

typedef struct {
    int      ok;
    size_t   wire_n;
    uint8_t *recovered;
    size_t   recovered_n;
    char     err_msg[256];
} run_result_t;

static void result_set_err(run_result_t *r, const char *fmt, ...)
{
    r->ok = 0;
    if (r->recovered != NULL) {
        free(r->recovered);
        r->recovered = NULL;
    }
    r->recovered_n = 0;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(r->err_msg, sizeof(r->err_msg), fmt, ap);
    va_end(ap);
}

static void result_clear(run_result_t *r)
{
    if (r->recovered != NULL) {
        free(r->recovered);
        r->recovered = NULL;
    }
    r->recovered_n = 0;
}

/* Encryptor / seed factories ---------------------------------------- */

/*
 * Apply the eitb-wide ITB config to the process-global setters.
 *
 * The configuration uses NonceBits=128 (the libitb default) as a
 * deliberate baseline pick for the C eitb matrix. The Go-side tools/eitb
 * uses NonceBits=512; the C binding's streams.c hdr_buf is sized for
 * NonceBits=512 chunk headers (128 bytes, accommodating the 64+4 = 68
 * byte field), so the binding code path supports NonceBits=512 — but
 * the Easy stream_decrypt_auth path in the encryptor object surface
 * presently relies on the process-global nonce_bits matching the
 * per-encryptor value, and aead-easy-io does not invoke the global
 * setter inside its runner. Keeping the matrix at the libitb default
 * avoids that decoupling for the example harness; the per-encryptor
 * knobs (BarrierFill / BitSoup / LockSoup) match the Go-side defaults.
 */
static int apply_global_knobs(void)
{
    if (itb_set_nonce_bits(128) != ITB_OK) return -1;
    if (itb_set_barrier_fill(4) != ITB_OK) return -1;
    if (itb_set_bit_soup(1) != ITB_OK) return -1;
    if (itb_set_lock_soup(1) != ITB_OK) return -1;
    if (itb_set_lock_batch(1) != ITB_OK) return -1;
    return 0;
}

static int make_easy_encryptor(int with_mac, int key_bits, itb_encryptor_t **out)
{
    /* Easy Mode encryptor matching the Go-side eitb (Areion-SoEM-512,
     * 1024-bit key for streaming, 2048-bit key for single-message).
     * NonceBits stays at the libitb default 128 — see the comment on
     * apply_global_knobs() for the rationale. */
    const char *mac_name = with_mac ? "hmac-blake3" : "";
    itb_status_t s = itb_encryptor_new("areion512", key_bits, mac_name, 1, out);
    if (s != ITB_OK) return -1;
    if (itb_encryptor_set_nonce_bits(*out, 128) != ITB_OK) return -1;
    if (itb_encryptor_set_barrier_fill(*out, 4) != ITB_OK) return -1;
    if (itb_encryptor_set_bit_soup(*out, 1) != ITB_OK) return -1;
    if (itb_encryptor_set_lock_soup(*out, 1) != ITB_OK) return -1;
    if (itb_encryptor_set_lock_batch(*out, 1) != ITB_OK) return -1;
    return 0;
}

static int make_seeds_512(int n, int key_bits, itb_seed_t **out)
{
    for (int i = 0; i < n; i++) out[i] = NULL;
    for (int i = 0; i < n; i++) {
        if (itb_seed_new("areion512", key_bits, &out[i]) != ITB_OK) {
            for (int j = 0; j < i; j++) {
                itb_seed_free(out[j]);
                out[j] = NULL;
            }
            return -1;
        }
    }
    return 0;
}

static void free_seeds(int n, itb_seed_t **arr)
{
    for (int i = 0; i < n; i++) {
        itb_seed_free(arr[i]);
        arr[i] = NULL;
    }
}

/* ------------------------------------------------------------------ */
/* 1. aead-easy-io — Streaming AEAD Easy (MAC Authenticated, IO-Driven)
 * ------------------------------------------------------------------ */
/*
 * Sender uses itb_encryptor_stream_encrypt_auth backed by an in-memory
 * collector; the entire emitted bytestream (32-byte stream prefix +
 * per-chunk wire) is then wrapped end-to-end through one
 * itb_wrap_stream_writer_t session. Receiver reverses with
 * itb_unwrap_stream_reader_t feeding the inner-stream decoder.
 */
static void run_aead_easy_io(itb_wrapper_cipher_t cipher,
                             const uint8_t *plaintext, size_t pt_len,
                             run_result_t *r)
{
    itb_encryptor_t *enc = NULL;
    if (make_easy_encryptor(/*with_mac=*/1, 1024, &enc) != 0) {
        result_set_err(r, "easy encryptor: %s", itb_last_error());
        return;
    }

    grow_t inner = {0};
    mread_t pt_src = { plaintext, pt_len, 0 };
    if (itb_encryptor_stream_encrypt_auth(
            enc, mread_read, &pt_src, grow_write, &inner, STREAM_CHUNK_SIZE) != ITB_OK) {
        result_set_err(r, "stream_encrypt_auth: %s", itb_last_error());
        free(inner.data);
        itb_encryptor_free(enc);
        return;
    }

    uint8_t *outer_key = NULL;
    size_t outer_key_len = 0;
    if (itb_wrapper_generate_key(cipher, &outer_key, &outer_key_len) != ITB_OK) {
        result_set_err(r, "generate_key: %s", itb_last_error());
        free(inner.data);
        itb_encryptor_free(enc);
        return;
    }

    /* Wrap inner bytes through one keystream session. The wire is
     * `nonce || ks-XOR(inner)`. */
    uint8_t nonce_buf[16] = {0};
    itb_wrap_stream_writer_t *ww = NULL;
    if (itb_wrap_stream_writer_new(cipher, outer_key, outer_key_len,
                                   nonce_buf, sizeof(nonce_buf), &ww) != ITB_OK) {
        result_set_err(r, "wrap_stream_writer_new: %s", itb_last_error());
        free(inner.data);
        itb_buffer_free(outer_key);
        itb_encryptor_free(enc);
        return;
    }
    size_t nlen = 0;
    (void) itb_wrapper_nonce_size(cipher, &nlen);

    size_t wire_len = nlen + inner.len;
    uint8_t *wire = (uint8_t *) malloc(wire_len);
    if (wire == NULL) {
        result_set_err(r, "wire malloc");
        itb_wrap_stream_writer_free(ww);
        free(inner.data);
        itb_buffer_free(outer_key);
        itb_encryptor_free(enc);
        return;
    }
    memcpy(wire, nonce_buf, nlen);
    if (itb_wrap_stream_writer_update(ww, inner.data, inner.len,
                                      wire + nlen, inner.len) != ITB_OK) {
        result_set_err(r, "wrap_stream_writer_update: %s", itb_last_error());
        free(wire);
        itb_wrap_stream_writer_free(ww);
        free(inner.data);
        itb_buffer_free(outer_key);
        itb_encryptor_free(enc);
        return;
    }
    itb_wrap_stream_writer_free(ww);
    free(inner.data);
    inner.data = NULL;

    /* Receiver — strip the leading nonce, unwrap the body, decrypt. */
    itb_unwrap_stream_reader_t *ur = NULL;
    if (itb_unwrap_stream_reader_new(cipher, outer_key, outer_key_len,
                                     wire, nlen, &ur) != ITB_OK) {
        result_set_err(r, "unwrap_stream_reader_new: %s", itb_last_error());
        free(wire);
        itb_buffer_free(outer_key);
        itb_encryptor_free(enc);
        return;
    }
    uint8_t *inner_recovered = (uint8_t *) malloc(wire_len - nlen);
    if (inner_recovered == NULL) {
        result_set_err(r, "inner_recovered malloc");
        itb_unwrap_stream_reader_free(ur);
        free(wire);
        itb_buffer_free(outer_key);
        itb_encryptor_free(enc);
        return;
    }
    if (itb_unwrap_stream_reader_update(ur, wire + nlen, wire_len - nlen,
                                        inner_recovered, wire_len - nlen) != ITB_OK) {
        result_set_err(r, "unwrap_stream_reader_update: %s", itb_last_error());
        free(inner_recovered);
        itb_unwrap_stream_reader_free(ur);
        free(wire);
        itb_buffer_free(outer_key);
        itb_encryptor_free(enc);
        return;
    }
    itb_unwrap_stream_reader_free(ur);

    grow_t plaintext_out = {0};
    mread_t inner_src = { inner_recovered, wire_len - nlen, 0 };
    if (itb_encryptor_stream_decrypt_auth(
            enc, mread_read, &inner_src, grow_write, &plaintext_out,
            STREAM_CHUNK_SIZE) != ITB_OK) {
        result_set_err(r, "stream_decrypt_auth: %s", itb_last_error());
        free(inner_recovered);
        free(plaintext_out.data);
        free(wire);
        itb_buffer_free(outer_key);
        itb_encryptor_free(enc);
        return;
    }

    r->ok = 1;
    r->wire_n = wire_len;
    r->recovered = plaintext_out.data;
    r->recovered_n = plaintext_out.len;

    free(inner_recovered);
    free(wire);
    itb_buffer_free(outer_key);
    itb_encryptor_free(enc);
}

/* ------------------------------------------------------------------ */
/* 2. aead-lowlevel-io — Streaming AEAD Low-Level (MAC Authenticated, IO-Driven)
 * ------------------------------------------------------------------ */
/*
 * Drives itb_stream_encrypt_auth / itb_stream_decrypt_auth over the
 * wrap-writer / unwrap-reader. Three explicit Areion-SoEM-512 seeds
 * (1024-bit) plus an HMAC-BLAKE3 MAC handle.
 */
static void run_aead_lowlevel_io(itb_wrapper_cipher_t cipher,
                                 const uint8_t *plaintext, size_t pt_len,
                                 run_result_t *r)
{
    if (apply_global_knobs() != 0) {
        result_set_err(r, "apply_global_knobs: %s", itb_last_error());
        return;
    }

    itb_seed_t *seeds[3] = {NULL, NULL, NULL};
    if (make_seeds_512(3, 1024, seeds) != 0) {
        result_set_err(r, "make_seeds_512: %s", itb_last_error());
        return;
    }

    uint8_t mac_key[32];
    if (read_csprng(mac_key, sizeof(mac_key)) != 0) {
        result_set_err(r, "csprng read");
        free_seeds(3, seeds);
        return;
    }
    itb_mac_t *mac = NULL;
    if (itb_mac_new("hmac-blake3", mac_key, sizeof(mac_key), &mac) != ITB_OK) {
        result_set_err(r, "mac_new: %s", itb_last_error());
        free_seeds(3, seeds);
        return;
    }

    grow_t inner = {0};
    mread_t pt_src = { plaintext, pt_len, 0 };
    if (itb_stream_encrypt_auth(seeds[0], seeds[1], seeds[2], mac,
                                mread_read, &pt_src, grow_write, &inner,
                                STREAM_CHUNK_SIZE) != ITB_OK) {
        result_set_err(r, "stream_encrypt_auth: %s", itb_last_error());
        free(inner.data);
        itb_mac_free(mac);
        free_seeds(3, seeds);
        return;
    }

    uint8_t *outer_key = NULL;
    size_t outer_key_len = 0;
    if (itb_wrapper_generate_key(cipher, &outer_key, &outer_key_len) != ITB_OK) {
        result_set_err(r, "generate_key: %s", itb_last_error());
        free(inner.data);
        itb_mac_free(mac);
        free_seeds(3, seeds);
        return;
    }

    uint8_t nonce_buf[16] = {0};
    itb_wrap_stream_writer_t *ww = NULL;
    if (itb_wrap_stream_writer_new(cipher, outer_key, outer_key_len,
                                   nonce_buf, sizeof(nonce_buf), &ww) != ITB_OK) {
        result_set_err(r, "wrap_stream_writer_new: %s", itb_last_error());
        free(inner.data);
        itb_buffer_free(outer_key);
        itb_mac_free(mac);
        free_seeds(3, seeds);
        return;
    }
    size_t nlen = 0;
    (void) itb_wrapper_nonce_size(cipher, &nlen);
    size_t wire_len = nlen + inner.len;
    uint8_t *wire = (uint8_t *) malloc(wire_len);
    if (wire == NULL) {
        result_set_err(r, "wire malloc");
        itb_wrap_stream_writer_free(ww);
        free(inner.data);
        itb_buffer_free(outer_key);
        itb_mac_free(mac);
        free_seeds(3, seeds);
        return;
    }
    memcpy(wire, nonce_buf, nlen);
    if (itb_wrap_stream_writer_update(ww, inner.data, inner.len,
                                      wire + nlen, inner.len) != ITB_OK) {
        result_set_err(r, "wrap_stream_writer_update: %s", itb_last_error());
        free(wire);
        itb_wrap_stream_writer_free(ww);
        free(inner.data);
        itb_buffer_free(outer_key);
        itb_mac_free(mac);
        free_seeds(3, seeds);
        return;
    }
    itb_wrap_stream_writer_free(ww);
    free(inner.data);
    inner.data = NULL;

    itb_unwrap_stream_reader_t *ur = NULL;
    if (itb_unwrap_stream_reader_new(cipher, outer_key, outer_key_len,
                                     wire, nlen, &ur) != ITB_OK) {
        result_set_err(r, "unwrap_stream_reader_new: %s", itb_last_error());
        free(wire);
        itb_buffer_free(outer_key);
        itb_mac_free(mac);
        free_seeds(3, seeds);
        return;
    }
    uint8_t *inner_recovered = (uint8_t *) malloc(wire_len - nlen);
    if (inner_recovered == NULL) {
        result_set_err(r, "inner_recovered malloc");
        itb_unwrap_stream_reader_free(ur);
        free(wire);
        itb_buffer_free(outer_key);
        itb_mac_free(mac);
        free_seeds(3, seeds);
        return;
    }
    if (itb_unwrap_stream_reader_update(ur, wire + nlen, wire_len - nlen,
                                        inner_recovered, wire_len - nlen) != ITB_OK) {
        result_set_err(r, "unwrap_stream_reader_update: %s", itb_last_error());
        free(inner_recovered);
        itb_unwrap_stream_reader_free(ur);
        free(wire);
        itb_buffer_free(outer_key);
        itb_mac_free(mac);
        free_seeds(3, seeds);
        return;
    }
    itb_unwrap_stream_reader_free(ur);

    grow_t plaintext_out = {0};
    mread_t inner_src = { inner_recovered, wire_len - nlen, 0 };
    if (itb_stream_decrypt_auth(seeds[0], seeds[1], seeds[2], mac,
                                mread_read, &inner_src, grow_write, &plaintext_out,
                                STREAM_CHUNK_SIZE) != ITB_OK) {
        result_set_err(r, "stream_decrypt_auth: %s", itb_last_error());
        free(inner_recovered);
        free(plaintext_out.data);
        free(wire);
        itb_buffer_free(outer_key);
        itb_mac_free(mac);
        free_seeds(3, seeds);
        return;
    }

    r->ok = 1;
    r->wire_n = wire_len;
    r->recovered = plaintext_out.data;
    r->recovered_n = plaintext_out.len;

    free(inner_recovered);
    free(wire);
    itb_buffer_free(outer_key);
    itb_mac_free(mac);
    free_seeds(3, seeds);
}

/* ------------------------------------------------------------------ */
/* 3. noaead-easy-userloop — Streaming Easy (No MAC, User-Driven Loop)
 * ------------------------------------------------------------------ */
/*
 * Per-chunk itb_encryptor_encrypt() / decrypt() with caller-side
 * framing through the wrap-writer. Each chunk is emitted as
 * `u32_LE_len || ct` through the keystream so neither the length
 * prefix nor the body appears in cleartext on the wire.
 */
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

static int wire_grow(grow_t *g, const uint8_t *src, size_t n)
{
    return grow_write(g, src, n);
}

static void run_noaead_easy_userloop(itb_wrapper_cipher_t cipher,
                                     const uint8_t *plaintext, size_t pt_len,
                                     run_result_t *r)
{
    itb_encryptor_t *enc = NULL;
    if (make_easy_encryptor(/*with_mac=*/0, 1024, &enc) != 0) {
        result_set_err(r, "easy encryptor: %s", itb_last_error());
        return;
    }

    uint8_t *outer_key = NULL;
    size_t outer_key_len = 0;
    if (itb_wrapper_generate_key(cipher, &outer_key, &outer_key_len) != ITB_OK) {
        result_set_err(r, "generate_key: %s", itb_last_error());
        itb_encryptor_free(enc);
        return;
    }

    /* Sender — wrap-writer accumulating into wire_buf. */
    grow_t wire_buf = {0};
    uint8_t nonce_buf[16] = {0};
    itb_wrap_stream_writer_t *ww = NULL;
    if (itb_wrap_stream_writer_new(cipher, outer_key, outer_key_len,
                                   nonce_buf, sizeof(nonce_buf), &ww) != ITB_OK) {
        result_set_err(r, "wrap_stream_writer_new: %s", itb_last_error());
        free(wire_buf.data);
        itb_buffer_free(outer_key);
        itb_encryptor_free(enc);
        return;
    }
    size_t nlen = 0;
    (void) itb_wrapper_nonce_size(cipher, &nlen);
    /* Emit nonce as wire prefix. */
    if (wire_grow(&wire_buf, nonce_buf, nlen) != 0) {
        result_set_err(r, "wire_grow nonce");
        itb_wrap_stream_writer_free(ww);
        free(wire_buf.data);
        itb_buffer_free(outer_key);
        itb_encryptor_free(enc);
        return;
    }

    for (size_t off = 0; off < pt_len; off += STREAM_CHUNK_SIZE) {
        size_t take = pt_len - off;
        if (take > STREAM_CHUNK_SIZE) take = STREAM_CHUNK_SIZE;
        uint8_t *ct = NULL;
        size_t ct_len = 0;
        if (itb_encryptor_encrypt(enc, plaintext + off, take, &ct, &ct_len) != ITB_OK) {
            result_set_err(r, "encryptor_encrypt: %s", itb_last_error());
            itb_wrap_stream_writer_free(ww);
            free(wire_buf.data);
            itb_buffer_free(outer_key);
            itb_encryptor_free(enc);
            return;
        }
        uint8_t hdr[4];
        put_u32_le(hdr, (uint32_t) ct_len);
        uint8_t hdr_xor[4];
        if (itb_wrap_stream_writer_update(ww, hdr, 4, hdr_xor, 4) != ITB_OK) {
            result_set_err(r, "wrap update hdr: %s", itb_last_error());
            itb_buffer_free(ct);
            itb_wrap_stream_writer_free(ww);
            free(wire_buf.data);
            itb_buffer_free(outer_key);
            itb_encryptor_free(enc);
            return;
        }
        if (wire_grow(&wire_buf, hdr_xor, 4) != 0) {
            result_set_err(r, "wire_grow hdr");
            itb_buffer_free(ct);
            itb_wrap_stream_writer_free(ww);
            free(wire_buf.data);
            itb_buffer_free(outer_key);
            itb_encryptor_free(enc);
            return;
        }
        uint8_t *ct_xor = (uint8_t *) malloc(ct_len);
        if (ct_xor == NULL) {
            result_set_err(r, "ct_xor malloc");
            itb_buffer_free(ct);
            itb_wrap_stream_writer_free(ww);
            free(wire_buf.data);
            itb_buffer_free(outer_key);
            itb_encryptor_free(enc);
            return;
        }
        if (itb_wrap_stream_writer_update(ww, ct, ct_len, ct_xor, ct_len) != ITB_OK) {
            result_set_err(r, "wrap update ct: %s", itb_last_error());
            free(ct_xor);
            itb_buffer_free(ct);
            itb_wrap_stream_writer_free(ww);
            free(wire_buf.data);
            itb_buffer_free(outer_key);
            itb_encryptor_free(enc);
            return;
        }
        if (wire_grow(&wire_buf, ct_xor, ct_len) != 0) {
            result_set_err(r, "wire_grow ct");
            free(ct_xor);
            itb_buffer_free(ct);
            itb_wrap_stream_writer_free(ww);
            free(wire_buf.data);
            itb_buffer_free(outer_key);
            itb_encryptor_free(enc);
            return;
        }
        free(ct_xor);
        itb_buffer_free(ct);
    }
    itb_wrap_stream_writer_free(ww);

    /* Receiver — read u32_LE length then body through the unwrap-
     * reader, looping until EOF. Accumulate decrypted plaintext
     * into pt_out. */
    if (wire_buf.len < nlen) {
        result_set_err(r, "wire shorter than nonce");
        free(wire_buf.data);
        itb_buffer_free(outer_key);
        itb_encryptor_free(enc);
        return;
    }
    itb_unwrap_stream_reader_t *ur = NULL;
    if (itb_unwrap_stream_reader_new(cipher, outer_key, outer_key_len,
                                     wire_buf.data, nlen, &ur) != ITB_OK) {
        result_set_err(r, "unwrap_stream_reader_new: %s", itb_last_error());
        free(wire_buf.data);
        itb_buffer_free(outer_key);
        itb_encryptor_free(enc);
        return;
    }
    grow_t pt_out = {0};
    size_t off = nlen;
    while (off < wire_buf.len) {
        if (off + 4 > wire_buf.len) {
            result_set_err(r, "truncated length prefix");
            itb_unwrap_stream_reader_free(ur);
            free(pt_out.data);
            free(wire_buf.data);
            itb_buffer_free(outer_key);
            itb_encryptor_free(enc);
            return;
        }
        uint8_t hdr[4];
        if (itb_unwrap_stream_reader_update(ur, wire_buf.data + off, 4, hdr, 4) != ITB_OK) {
            result_set_err(r, "unwrap update hdr: %s", itb_last_error());
            itb_unwrap_stream_reader_free(ur);
            free(pt_out.data);
            free(wire_buf.data);
            itb_buffer_free(outer_key);
            itb_encryptor_free(enc);
            return;
        }
        off += 4;
        uint32_t clen = get_u32_le(hdr);
        if (off + clen > wire_buf.len) {
            result_set_err(r, "truncated chunk body");
            itb_unwrap_stream_reader_free(ur);
            free(pt_out.data);
            free(wire_buf.data);
            itb_buffer_free(outer_key);
            itb_encryptor_free(enc);
            return;
        }
        uint8_t *ct = (uint8_t *) malloc(clen);
        if (ct == NULL) {
            result_set_err(r, "ct malloc");
            itb_unwrap_stream_reader_free(ur);
            free(pt_out.data);
            free(wire_buf.data);
            itb_buffer_free(outer_key);
            itb_encryptor_free(enc);
            return;
        }
        if (itb_unwrap_stream_reader_update(ur, wire_buf.data + off, clen, ct, clen) != ITB_OK) {
            result_set_err(r, "unwrap update ct: %s", itb_last_error());
            free(ct);
            itb_unwrap_stream_reader_free(ur);
            free(pt_out.data);
            free(wire_buf.data);
            itb_buffer_free(outer_key);
            itb_encryptor_free(enc);
            return;
        }
        off += clen;
        uint8_t *pt = NULL;
        size_t pt_len_chunk = 0;
        if (itb_encryptor_decrypt(enc, ct, clen, &pt, &pt_len_chunk) != ITB_OK) {
            result_set_err(r, "encryptor_decrypt: %s", itb_last_error());
            free(ct);
            itb_unwrap_stream_reader_free(ur);
            free(pt_out.data);
            free(wire_buf.data);
            itb_buffer_free(outer_key);
            itb_encryptor_free(enc);
            return;
        }
        free(ct);
        if (grow_write(&pt_out, pt, pt_len_chunk) != 0) {
            result_set_err(r, "grow_write pt");
            itb_buffer_free(pt);
            itb_unwrap_stream_reader_free(ur);
            free(pt_out.data);
            free(wire_buf.data);
            itb_buffer_free(outer_key);
            itb_encryptor_free(enc);
            return;
        }
        itb_buffer_free(pt);
    }
    itb_unwrap_stream_reader_free(ur);

    r->ok = 1;
    r->wire_n = wire_buf.len;
    r->recovered = pt_out.data;
    r->recovered_n = pt_out.len;

    free(wire_buf.data);
    itb_buffer_free(outer_key);
    itb_encryptor_free(enc);
}

/* ------------------------------------------------------------------ */
/* 4. noaead-lowlevel-userloop — Streaming Low-Level (No MAC, User-Driven Loop)
 * ------------------------------------------------------------------ */
static void run_noaead_lowlevel_userloop(itb_wrapper_cipher_t cipher,
                                         const uint8_t *plaintext, size_t pt_len,
                                         run_result_t *r)
{
    if (apply_global_knobs() != 0) {
        result_set_err(r, "apply_global_knobs: %s", itb_last_error());
        return;
    }
    itb_seed_t *seeds[3] = {NULL, NULL, NULL};
    if (make_seeds_512(3, 1024, seeds) != 0) {
        result_set_err(r, "make_seeds_512: %s", itb_last_error());
        return;
    }
    uint8_t *outer_key = NULL;
    size_t outer_key_len = 0;
    if (itb_wrapper_generate_key(cipher, &outer_key, &outer_key_len) != ITB_OK) {
        result_set_err(r, "generate_key: %s", itb_last_error());
        free_seeds(3, seeds);
        return;
    }

    grow_t wire_buf = {0};
    uint8_t nonce_buf[16] = {0};
    itb_wrap_stream_writer_t *ww = NULL;
    if (itb_wrap_stream_writer_new(cipher, outer_key, outer_key_len,
                                   nonce_buf, sizeof(nonce_buf), &ww) != ITB_OK) {
        result_set_err(r, "wrap_stream_writer_new: %s", itb_last_error());
        free(wire_buf.data);
        itb_buffer_free(outer_key);
        free_seeds(3, seeds);
        return;
    }
    size_t nlen = 0;
    (void) itb_wrapper_nonce_size(cipher, &nlen);
    if (wire_grow(&wire_buf, nonce_buf, nlen) != 0) {
        result_set_err(r, "wire_grow nonce");
        itb_wrap_stream_writer_free(ww);
        free(wire_buf.data);
        itb_buffer_free(outer_key);
        free_seeds(3, seeds);
        return;
    }
    for (size_t off = 0; off < pt_len; off += STREAM_CHUNK_SIZE) {
        size_t take = pt_len - off;
        if (take > STREAM_CHUNK_SIZE) take = STREAM_CHUNK_SIZE;
        uint8_t *ct = NULL;
        size_t ct_len = 0;
        if (itb_encrypt(seeds[0], seeds[1], seeds[2],
                        plaintext + off, take, &ct, &ct_len) != ITB_OK) {
            result_set_err(r, "itb_encrypt: %s", itb_last_error());
            itb_wrap_stream_writer_free(ww);
            free(wire_buf.data);
            itb_buffer_free(outer_key);
            free_seeds(3, seeds);
            return;
        }
        uint8_t hdr[4];
        put_u32_le(hdr, (uint32_t) ct_len);
        uint8_t hdr_xor[4];
        if (itb_wrap_stream_writer_update(ww, hdr, 4, hdr_xor, 4) != ITB_OK) {
            result_set_err(r, "wrap update hdr: %s", itb_last_error());
            itb_buffer_free(ct);
            itb_wrap_stream_writer_free(ww);
            free(wire_buf.data);
            itb_buffer_free(outer_key);
            free_seeds(3, seeds);
            return;
        }
        if (wire_grow(&wire_buf, hdr_xor, 4) != 0) {
            result_set_err(r, "wire_grow hdr");
            itb_buffer_free(ct);
            itb_wrap_stream_writer_free(ww);
            free(wire_buf.data);
            itb_buffer_free(outer_key);
            free_seeds(3, seeds);
            return;
        }
        uint8_t *ct_xor = (uint8_t *) malloc(ct_len);
        if (ct_xor == NULL) {
            result_set_err(r, "ct_xor malloc");
            itb_buffer_free(ct);
            itb_wrap_stream_writer_free(ww);
            free(wire_buf.data);
            itb_buffer_free(outer_key);
            free_seeds(3, seeds);
            return;
        }
        if (itb_wrap_stream_writer_update(ww, ct, ct_len, ct_xor, ct_len) != ITB_OK) {
            result_set_err(r, "wrap update ct: %s", itb_last_error());
            free(ct_xor);
            itb_buffer_free(ct);
            itb_wrap_stream_writer_free(ww);
            free(wire_buf.data);
            itb_buffer_free(outer_key);
            free_seeds(3, seeds);
            return;
        }
        if (wire_grow(&wire_buf, ct_xor, ct_len) != 0) {
            result_set_err(r, "wire_grow ct");
            free(ct_xor);
            itb_buffer_free(ct);
            itb_wrap_stream_writer_free(ww);
            free(wire_buf.data);
            itb_buffer_free(outer_key);
            free_seeds(3, seeds);
            return;
        }
        free(ct_xor);
        itb_buffer_free(ct);
    }
    itb_wrap_stream_writer_free(ww);

    if (wire_buf.len < nlen) {
        result_set_err(r, "wire shorter than nonce");
        free(wire_buf.data);
        itb_buffer_free(outer_key);
        free_seeds(3, seeds);
        return;
    }
    itb_unwrap_stream_reader_t *ur = NULL;
    if (itb_unwrap_stream_reader_new(cipher, outer_key, outer_key_len,
                                     wire_buf.data, nlen, &ur) != ITB_OK) {
        result_set_err(r, "unwrap_stream_reader_new: %s", itb_last_error());
        free(wire_buf.data);
        itb_buffer_free(outer_key);
        free_seeds(3, seeds);
        return;
    }
    grow_t pt_out = {0};
    size_t off = nlen;
    while (off < wire_buf.len) {
        if (off + 4 > wire_buf.len) {
            result_set_err(r, "truncated length prefix");
            itb_unwrap_stream_reader_free(ur);
            free(pt_out.data);
            free(wire_buf.data);
            itb_buffer_free(outer_key);
            free_seeds(3, seeds);
            return;
        }
        uint8_t hdr[4];
        if (itb_unwrap_stream_reader_update(ur, wire_buf.data + off, 4, hdr, 4) != ITB_OK) {
            result_set_err(r, "unwrap update hdr: %s", itb_last_error());
            itb_unwrap_stream_reader_free(ur);
            free(pt_out.data);
            free(wire_buf.data);
            itb_buffer_free(outer_key);
            free_seeds(3, seeds);
            return;
        }
        off += 4;
        uint32_t clen = get_u32_le(hdr);
        if (off + clen > wire_buf.len) {
            result_set_err(r, "truncated chunk body");
            itb_unwrap_stream_reader_free(ur);
            free(pt_out.data);
            free(wire_buf.data);
            itb_buffer_free(outer_key);
            free_seeds(3, seeds);
            return;
        }
        uint8_t *ct = (uint8_t *) malloc(clen);
        if (ct == NULL) {
            result_set_err(r, "ct malloc");
            itb_unwrap_stream_reader_free(ur);
            free(pt_out.data);
            free(wire_buf.data);
            itb_buffer_free(outer_key);
            free_seeds(3, seeds);
            return;
        }
        if (itb_unwrap_stream_reader_update(ur, wire_buf.data + off, clen, ct, clen) != ITB_OK) {
            result_set_err(r, "unwrap update ct: %s", itb_last_error());
            free(ct);
            itb_unwrap_stream_reader_free(ur);
            free(pt_out.data);
            free(wire_buf.data);
            itb_buffer_free(outer_key);
            free_seeds(3, seeds);
            return;
        }
        off += clen;
        uint8_t *pt = NULL;
        size_t pt_len_chunk = 0;
        if (itb_decrypt(seeds[0], seeds[1], seeds[2],
                        ct, clen, &pt, &pt_len_chunk) != ITB_OK) {
            result_set_err(r, "itb_decrypt: %s", itb_last_error());
            free(ct);
            itb_unwrap_stream_reader_free(ur);
            free(pt_out.data);
            free(wire_buf.data);
            itb_buffer_free(outer_key);
            free_seeds(3, seeds);
            return;
        }
        free(ct);
        if (grow_write(&pt_out, pt, pt_len_chunk) != 0) {
            result_set_err(r, "grow_write pt");
            itb_buffer_free(pt);
            itb_unwrap_stream_reader_free(ur);
            free(pt_out.data);
            free(wire_buf.data);
            itb_buffer_free(outer_key);
            free_seeds(3, seeds);
            return;
        }
        itb_buffer_free(pt);
    }
    itb_unwrap_stream_reader_free(ur);

    r->ok = 1;
    r->wire_n = wire_buf.len;
    r->recovered = pt_out.data;
    r->recovered_n = pt_out.len;

    free(wire_buf.data);
    itb_buffer_free(outer_key);
    free_seeds(3, seeds);
}

/* ------------------------------------------------------------------ */
/* 5. message-easy-nomac — Easy Single Message, No MAC
 * ------------------------------------------------------------------ */
/*
 * Default eitb path mirrors tools/eitb/main.go:
 * itb_wrap_in_place (mutates the ciphertext buffer in place) +
 * itb_unwrap_in_place. The commented `itb_wrap` / `itb_unwrap`
 * alternatives respect immutability of `encrypted` / `wire` at the
 * cost of an extra allocation per call.
 */
static void run_message_easy_nomac(itb_wrapper_cipher_t cipher,
                                   const uint8_t *plaintext, size_t pt_len,
                                   run_result_t *r)
{
    itb_encryptor_t *enc = NULL;
    if (make_easy_encryptor(/*with_mac=*/0, 2048, &enc) != 0) {
        result_set_err(r, "easy encryptor: %s", itb_last_error());
        return;
    }

    uint8_t *encrypted = NULL;
    size_t encrypted_len = 0;
    if (itb_encryptor_encrypt(enc, plaintext, pt_len,
                              &encrypted, &encrypted_len) != ITB_OK) {
        result_set_err(r, "encryptor_encrypt: %s", itb_last_error());
        itb_encryptor_free(enc);
        return;
    }

    uint8_t *outer_key = NULL;
    size_t outer_key_len = 0;
    if (itb_wrapper_generate_key(cipher, &outer_key, &outer_key_len) != ITB_OK) {
        result_set_err(r, "generate_key: %s", itb_last_error());
        itb_buffer_free(encrypted);
        itb_encryptor_free(enc);
        return;
    }

    /* Wrap respects immutability of `encrypted` (allocates a fresh wire buffer).
     * uint8_t *wire = NULL; size_t wire_len = 0;
     * if (itb_wrap(cipher, outer_key, outer_key_len, encrypted, encrypted_len,
     *              &wire, &wire_len) != ITB_OK) { ... }
     */
    uint8_t nonce_buf[16] = {0};
    if (itb_wrap_in_place(cipher, outer_key, outer_key_len,
                          encrypted, encrypted_len,
                          nonce_buf, sizeof(nonce_buf)) != ITB_OK) {
        result_set_err(r, "wrap_in_place: %s", itb_last_error());
        itb_buffer_free(encrypted);
        itb_buffer_free(outer_key);
        itb_encryptor_free(enc);
        return;
    }
    size_t nlen = 0;
    (void) itb_wrapper_nonce_size(cipher, &nlen);
    size_t wire_len = nlen + encrypted_len;
    uint8_t *wire = (uint8_t *) malloc(wire_len);
    if (wire == NULL) {
        result_set_err(r, "wire malloc");
        itb_buffer_free(encrypted);
        itb_buffer_free(outer_key);
        itb_encryptor_free(enc);
        return;
    }
    memcpy(wire, nonce_buf, nlen);
    memcpy(wire + nlen, encrypted, encrypted_len);

    /* Unwrap respects immutability of `wire` (allocates a fresh recovered buffer).
     * uint8_t *recovered = NULL; size_t recovered_len = 0;
     * if (itb_unwrap(cipher, outer_key, outer_key_len, wire, wire_len,
     *                &recovered, &recovered_len) != ITB_OK) { ... }
     */
    if (itb_unwrap_in_place(cipher, outer_key, outer_key_len, wire, wire_len) != ITB_OK) {
        result_set_err(r, "unwrap_in_place: %s", itb_last_error());
        free(wire);
        itb_buffer_free(encrypted);
        itb_buffer_free(outer_key);
        itb_encryptor_free(enc);
        return;
    }

    uint8_t *pt = NULL;
    size_t pt_recovered_len = 0;
    if (itb_encryptor_decrypt(enc, wire + nlen, encrypted_len, &pt, &pt_recovered_len) != ITB_OK) {
        result_set_err(r, "encryptor_decrypt: %s", itb_last_error());
        free(wire);
        itb_buffer_free(encrypted);
        itb_buffer_free(outer_key);
        itb_encryptor_free(enc);
        return;
    }

    /* Promote pt to a malloc'd buffer the caller-side runner owns. */
    uint8_t *recovered_copy = (uint8_t *) malloc(pt_recovered_len);
    if (recovered_copy == NULL) {
        result_set_err(r, "recovered_copy malloc");
        itb_buffer_free(pt);
        free(wire);
        itb_buffer_free(encrypted);
        itb_buffer_free(outer_key);
        itb_encryptor_free(enc);
        return;
    }
    memcpy(recovered_copy, pt, pt_recovered_len);

    r->ok = 1;
    r->wire_n = wire_len;
    r->recovered = recovered_copy;
    r->recovered_n = pt_recovered_len;

    itb_buffer_free(pt);
    free(wire);
    itb_buffer_free(encrypted);
    itb_buffer_free(outer_key);
    itb_encryptor_free(enc);
}

/* ------------------------------------------------------------------ */
/* 6. message-easy-auth — Easy Single Message, MAC Authenticated
 * ------------------------------------------------------------------ */
static void run_message_easy_auth(itb_wrapper_cipher_t cipher,
                                  const uint8_t *plaintext, size_t pt_len,
                                  run_result_t *r)
{
    itb_encryptor_t *enc = NULL;
    if (make_easy_encryptor(/*with_mac=*/1, 2048, &enc) != 0) {
        result_set_err(r, "easy encryptor: %s", itb_last_error());
        return;
    }

    uint8_t *encrypted = NULL;
    size_t encrypted_len = 0;
    if (itb_encryptor_encrypt_auth(enc, plaintext, pt_len, &encrypted, &encrypted_len) != ITB_OK) {
        result_set_err(r, "encryptor_encrypt_auth: %s", itb_last_error());
        itb_encryptor_free(enc);
        return;
    }

    uint8_t *outer_key = NULL;
    size_t outer_key_len = 0;
    if (itb_wrapper_generate_key(cipher, &outer_key, &outer_key_len) != ITB_OK) {
        result_set_err(r, "generate_key: %s", itb_last_error());
        itb_buffer_free(encrypted);
        itb_encryptor_free(enc);
        return;
    }

    /* See message-easy-nomac for the immutable-input alternative
     * (itb_wrap / itb_unwrap with separately-allocated buffers). */
    uint8_t nonce_buf[16] = {0};
    if (itb_wrap_in_place(cipher, outer_key, outer_key_len,
                          encrypted, encrypted_len,
                          nonce_buf, sizeof(nonce_buf)) != ITB_OK) {
        result_set_err(r, "wrap_in_place: %s", itb_last_error());
        itb_buffer_free(encrypted);
        itb_buffer_free(outer_key);
        itb_encryptor_free(enc);
        return;
    }
    size_t nlen = 0;
    (void) itb_wrapper_nonce_size(cipher, &nlen);
    size_t wire_len = nlen + encrypted_len;
    uint8_t *wire = (uint8_t *) malloc(wire_len);
    if (wire == NULL) {
        result_set_err(r, "wire malloc");
        itb_buffer_free(encrypted);
        itb_buffer_free(outer_key);
        itb_encryptor_free(enc);
        return;
    }
    memcpy(wire, nonce_buf, nlen);
    memcpy(wire + nlen, encrypted, encrypted_len);

    if (itb_unwrap_in_place(cipher, outer_key, outer_key_len, wire, wire_len) != ITB_OK) {
        result_set_err(r, "unwrap_in_place: %s", itb_last_error());
        free(wire);
        itb_buffer_free(encrypted);
        itb_buffer_free(outer_key);
        itb_encryptor_free(enc);
        return;
    }

    uint8_t *pt = NULL;
    size_t pt_recovered_len = 0;
    if (itb_encryptor_decrypt_auth(enc, wire + nlen, encrypted_len, &pt, &pt_recovered_len) != ITB_OK) {
        result_set_err(r, "encryptor_decrypt_auth: %s", itb_last_error());
        free(wire);
        itb_buffer_free(encrypted);
        itb_buffer_free(outer_key);
        itb_encryptor_free(enc);
        return;
    }
    uint8_t *recovered_copy = (uint8_t *) malloc(pt_recovered_len);
    if (recovered_copy == NULL) {
        result_set_err(r, "recovered_copy malloc");
        itb_buffer_free(pt);
        free(wire);
        itb_buffer_free(encrypted);
        itb_buffer_free(outer_key);
        itb_encryptor_free(enc);
        return;
    }
    memcpy(recovered_copy, pt, pt_recovered_len);

    r->ok = 1;
    r->wire_n = wire_len;
    r->recovered = recovered_copy;
    r->recovered_n = pt_recovered_len;

    itb_buffer_free(pt);
    free(wire);
    itb_buffer_free(encrypted);
    itb_buffer_free(outer_key);
    itb_encryptor_free(enc);
}

/* ------------------------------------------------------------------ */
/* 7. message-lowlevel-nomac — Low-Level Single Message, No MAC
 * ------------------------------------------------------------------ */
static void run_message_lowlevel_nomac(itb_wrapper_cipher_t cipher,
                                       const uint8_t *plaintext, size_t pt_len,
                                       run_result_t *r)
{
    if (apply_global_knobs() != 0) {
        result_set_err(r, "apply_global_knobs: %s", itb_last_error());
        return;
    }
    itb_seed_t *seeds[3] = {NULL, NULL, NULL};
    if (make_seeds_512(3, 2048, seeds) != 0) {
        result_set_err(r, "make_seeds_512: %s", itb_last_error());
        return;
    }
    uint8_t *encrypted = NULL;
    size_t encrypted_len = 0;
    if (itb_encrypt(seeds[0], seeds[1], seeds[2], plaintext, pt_len,
                    &encrypted, &encrypted_len) != ITB_OK) {
        result_set_err(r, "itb_encrypt: %s", itb_last_error());
        free_seeds(3, seeds);
        return;
    }
    uint8_t *outer_key = NULL;
    size_t outer_key_len = 0;
    if (itb_wrapper_generate_key(cipher, &outer_key, &outer_key_len) != ITB_OK) {
        result_set_err(r, "generate_key: %s", itb_last_error());
        itb_buffer_free(encrypted);
        free_seeds(3, seeds);
        return;
    }
    uint8_t nonce_buf[16] = {0};
    if (itb_wrap_in_place(cipher, outer_key, outer_key_len,
                          encrypted, encrypted_len,
                          nonce_buf, sizeof(nonce_buf)) != ITB_OK) {
        result_set_err(r, "wrap_in_place: %s", itb_last_error());
        itb_buffer_free(encrypted);
        itb_buffer_free(outer_key);
        free_seeds(3, seeds);
        return;
    }
    size_t nlen = 0;
    (void) itb_wrapper_nonce_size(cipher, &nlen);
    size_t wire_len = nlen + encrypted_len;
    uint8_t *wire = (uint8_t *) malloc(wire_len);
    if (wire == NULL) {
        result_set_err(r, "wire malloc");
        itb_buffer_free(encrypted);
        itb_buffer_free(outer_key);
        free_seeds(3, seeds);
        return;
    }
    memcpy(wire, nonce_buf, nlen);
    memcpy(wire + nlen, encrypted, encrypted_len);

    if (itb_unwrap_in_place(cipher, outer_key, outer_key_len, wire, wire_len) != ITB_OK) {
        result_set_err(r, "unwrap_in_place: %s", itb_last_error());
        free(wire);
        itb_buffer_free(encrypted);
        itb_buffer_free(outer_key);
        free_seeds(3, seeds);
        return;
    }
    uint8_t *pt = NULL;
    size_t pt_recovered_len = 0;
    if (itb_decrypt(seeds[0], seeds[1], seeds[2], wire + nlen, encrypted_len,
                    &pt, &pt_recovered_len) != ITB_OK) {
        result_set_err(r, "itb_decrypt: %s", itb_last_error());
        free(wire);
        itb_buffer_free(encrypted);
        itb_buffer_free(outer_key);
        free_seeds(3, seeds);
        return;
    }
    uint8_t *recovered_copy = (uint8_t *) malloc(pt_recovered_len);
    if (recovered_copy == NULL) {
        result_set_err(r, "recovered_copy malloc");
        itb_buffer_free(pt);
        free(wire);
        itb_buffer_free(encrypted);
        itb_buffer_free(outer_key);
        free_seeds(3, seeds);
        return;
    }
    memcpy(recovered_copy, pt, pt_recovered_len);
    r->ok = 1;
    r->wire_n = wire_len;
    r->recovered = recovered_copy;
    r->recovered_n = pt_recovered_len;
    itb_buffer_free(pt);
    free(wire);
    itb_buffer_free(encrypted);
    itb_buffer_free(outer_key);
    free_seeds(3, seeds);
}

/* ------------------------------------------------------------------ */
/* 8. message-lowlevel-auth — Low-Level Single Message, MAC Authenticated
 * ------------------------------------------------------------------ */
static void run_message_lowlevel_auth(itb_wrapper_cipher_t cipher,
                                      const uint8_t *plaintext, size_t pt_len,
                                      run_result_t *r)
{
    if (apply_global_knobs() != 0) {
        result_set_err(r, "apply_global_knobs: %s", itb_last_error());
        return;
    }
    itb_seed_t *seeds[3] = {NULL, NULL, NULL};
    if (make_seeds_512(3, 2048, seeds) != 0) {
        result_set_err(r, "make_seeds_512: %s", itb_last_error());
        return;
    }
    uint8_t mac_key[32];
    if (read_csprng(mac_key, sizeof(mac_key)) != 0) {
        result_set_err(r, "csprng read");
        free_seeds(3, seeds);
        return;
    }
    itb_mac_t *mac = NULL;
    if (itb_mac_new("hmac-blake3", mac_key, sizeof(mac_key), &mac) != ITB_OK) {
        result_set_err(r, "mac_new: %s", itb_last_error());
        free_seeds(3, seeds);
        return;
    }
    uint8_t *encrypted = NULL;
    size_t encrypted_len = 0;
    if (itb_encrypt_auth(seeds[0], seeds[1], seeds[2], mac, plaintext, pt_len,
                         &encrypted, &encrypted_len) != ITB_OK) {
        result_set_err(r, "itb_encrypt_auth: %s", itb_last_error());
        itb_mac_free(mac);
        free_seeds(3, seeds);
        return;
    }
    uint8_t *outer_key = NULL;
    size_t outer_key_len = 0;
    if (itb_wrapper_generate_key(cipher, &outer_key, &outer_key_len) != ITB_OK) {
        result_set_err(r, "generate_key: %s", itb_last_error());
        itb_buffer_free(encrypted);
        itb_mac_free(mac);
        free_seeds(3, seeds);
        return;
    }
    uint8_t nonce_buf[16] = {0};
    if (itb_wrap_in_place(cipher, outer_key, outer_key_len,
                          encrypted, encrypted_len,
                          nonce_buf, sizeof(nonce_buf)) != ITB_OK) {
        result_set_err(r, "wrap_in_place: %s", itb_last_error());
        itb_buffer_free(encrypted);
        itb_buffer_free(outer_key);
        itb_mac_free(mac);
        free_seeds(3, seeds);
        return;
    }
    size_t nlen = 0;
    (void) itb_wrapper_nonce_size(cipher, &nlen);
    size_t wire_len = nlen + encrypted_len;
    uint8_t *wire = (uint8_t *) malloc(wire_len);
    if (wire == NULL) {
        result_set_err(r, "wire malloc");
        itb_buffer_free(encrypted);
        itb_buffer_free(outer_key);
        itb_mac_free(mac);
        free_seeds(3, seeds);
        return;
    }
    memcpy(wire, nonce_buf, nlen);
    memcpy(wire + nlen, encrypted, encrypted_len);

    if (itb_unwrap_in_place(cipher, outer_key, outer_key_len, wire, wire_len) != ITB_OK) {
        result_set_err(r, "unwrap_in_place: %s", itb_last_error());
        free(wire);
        itb_buffer_free(encrypted);
        itb_buffer_free(outer_key);
        itb_mac_free(mac);
        free_seeds(3, seeds);
        return;
    }
    uint8_t *pt = NULL;
    size_t pt_recovered_len = 0;
    if (itb_decrypt_auth(seeds[0], seeds[1], seeds[2], mac, wire + nlen, encrypted_len,
                         &pt, &pt_recovered_len) != ITB_OK) {
        result_set_err(r, "itb_decrypt_auth: %s", itb_last_error());
        free(wire);
        itb_buffer_free(encrypted);
        itb_buffer_free(outer_key);
        itb_mac_free(mac);
        free_seeds(3, seeds);
        return;
    }
    uint8_t *recovered_copy = (uint8_t *) malloc(pt_recovered_len);
    if (recovered_copy == NULL) {
        result_set_err(r, "recovered_copy malloc");
        itb_buffer_free(pt);
        free(wire);
        itb_buffer_free(encrypted);
        itb_buffer_free(outer_key);
        itb_mac_free(mac);
        free_seeds(3, seeds);
        return;
    }
    memcpy(recovered_copy, pt, pt_recovered_len);
    r->ok = 1;
    r->wire_n = wire_len;
    r->recovered = recovered_copy;
    r->recovered_n = pt_recovered_len;
    itb_buffer_free(pt);
    free(wire);
    itb_buffer_free(encrypted);
    itb_buffer_free(outer_key);
    itb_mac_free(mac);
    free_seeds(3, seeds);
}

/* ------------------------------------------------------------------ */
/* Driver                                                              */
/* ------------------------------------------------------------------ */

typedef void (*example_fn)(itb_wrapper_cipher_t, const uint8_t *, size_t, run_result_t *);

typedef struct {
    const char *name;
    const char *description;
    size_t      payload_bytes;
    example_fn  fn;
} example_t;

static const example_t EXAMPLES[] = {
    { "aead-easy-io",             "Streaming AEAD Easy (MAC Authenticated, IO-Driven)",
      STREAM_BYTES, run_aead_easy_io },
    { "aead-lowlevel-io",         "Streaming AEAD Low-Level (MAC Authenticated, IO-Driven)",
      STREAM_BYTES, run_aead_lowlevel_io },
    { "noaead-easy-userloop",     "Streaming Easy (No MAC, User-Driven Loop)",
      STREAM_BYTES, run_noaead_easy_userloop },
    { "noaead-lowlevel-userloop", "Streaming Low-Level (No MAC, User-Driven Loop)",
      STREAM_BYTES, run_noaead_lowlevel_userloop },
    { "message-easy-nomac",       "Easy: Areion-SoEM-512 (No MAC, Single Message)",
      SINGLE_MESSAGE_BYTES, run_message_easy_nomac },
    { "message-easy-auth",        "Easy: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated, Single Message)",
      SINGLE_MESSAGE_BYTES, run_message_easy_auth },
    { "message-lowlevel-nomac",   "Low-Level: Areion-SoEM-512 (No MAC, Single Message)",
      SINGLE_MESSAGE_BYTES, run_message_lowlevel_nomac },
    { "message-lowlevel-auth",    "Low-Level: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated, Single Message)",
      SINGLE_MESSAGE_BYTES, run_message_lowlevel_auth },
};
#define EXAMPLES_N (sizeof(EXAMPLES) / sizeof(EXAMPLES[0]))

static int contains_substring(const char *haystack, const char *needle)
{
    if (needle == NULL || needle[0] == '\0') return 1;
    if (haystack == NULL) return 0;
    return strstr(haystack, needle) != NULL ? 1 : 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s [--example SUBSTR] [--cipher ciphername] [-v]\n",
            prog);
}

int main(int argc, char **argv)
{
    const char *example_filter = "";
    const char *cipher_filter = "";
    int verbose = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--example") == 0 && i + 1 < argc) {
            example_filter = argv[++i];
        } else if (strcmp(argv[i], "--cipher") == 0 && i + 1 < argc) {
            cipher_filter = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "unknown argument: %s\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    /* Process-wide ITB worker pool sizing. */
    if (itb_set_max_workers(0) != ITB_OK) {
        fprintf(stderr, "itb_set_max_workers(0) failed: %s\n", itb_last_error());
        return 1;
    }

    int pass = 0, fail = 0;
    for (size_t e = 0; e < EXAMPLES_N; e++) {
        const example_t *ex = &EXAMPLES[e];
        if (!contains_substring(ex->name, example_filter)) continue;
        for (size_t c = 0; c < CIPHER_COUNT; c++) {
            itb_wrapper_cipher_t cipher = CIPHERS[c];
            const char *cipher_name = itb_wrapper_cipher_name(cipher);
            if (cipher_filter[0] != '\0' && strcmp(cipher_name, cipher_filter) != 0) continue;

            uint8_t *plaintext = (uint8_t *) malloc(ex->payload_bytes);
            if (plaintext == NULL) {
                fprintf(stderr, "plaintext malloc failed\n");
                return 1;
            }
            if (read_csprng(plaintext, ex->payload_bytes) != 0) {
                fprintf(stderr, "csprng plaintext failed\n");
                free(plaintext);
                return 1;
            }
            uint8_t pt_digest[ITB_EITB_SHA256_DIGEST_LEN];
            itb_eitb_sha256(plaintext, ex->payload_bytes, pt_digest);

            run_result_t res = {0};
            ex->fn(cipher, plaintext, ex->payload_bytes, &res);

            int matches = (res.ok && res.recovered_n == ex->payload_bytes
                           && memcmp(res.recovered, plaintext, ex->payload_bytes) == 0);
            const char *tag = matches ? "PASS" : "FAIL";
            if (matches) pass++;
            else fail++;

            printf("[%s] %-26s + %-8s   pt=%zu wire=%zu",
                   tag, ex->name, cipher_name,
                   ex->payload_bytes, res.wire_n);
            if (!matches) {
                if (res.err_msg[0] != '\0') {
                    printf("  err: %s", res.err_msg);
                } else if (res.ok) {
                    char pt_hex[17];
                    char rcv_hex[17];
                    hex_short(pt_digest, pt_hex);
                    if (res.recovered != NULL) {
                        uint8_t rcv_digest[ITB_EITB_SHA256_DIGEST_LEN];
                        itb_eitb_sha256(res.recovered, res.recovered_n, rcv_digest);
                        hex_short(rcv_digest, rcv_hex);
                    } else {
                        memcpy(rcv_hex, "0000000000000000", 17);
                    }
                    printf("  err: plaintext hash mismatch (pt=%s rcv=%s)",
                           pt_hex, rcv_hex);
                }
            }
            printf("\n");

            if (verbose && matches) {
                /* Full sha256 for visual confirmation. */
                static const char hex_chars[] = "0123456789abcdef";
                char buf[ITB_EITB_SHA256_DIGEST_LEN * 2 + 1];
                for (int i = 0; i < ITB_EITB_SHA256_DIGEST_LEN; i++) {
                    buf[2 * i] = hex_chars[(pt_digest[i] >> 4) & 0xFu];
                    buf[2 * i + 1] = hex_chars[pt_digest[i] & 0xFu];
                }
                buf[ITB_EITB_SHA256_DIGEST_LEN * 2] = '\0';
                printf("       pt sha256:  %s\n", buf);
                uint8_t rcv_digest[ITB_EITB_SHA256_DIGEST_LEN];
                itb_eitb_sha256(res.recovered, res.recovered_n, rcv_digest);
                for (int i = 0; i < ITB_EITB_SHA256_DIGEST_LEN; i++) {
                    buf[2 * i] = hex_chars[(rcv_digest[i] >> 4) & 0xFu];
                    buf[2 * i + 1] = hex_chars[rcv_digest[i] & 0xFu];
                }
                buf[ITB_EITB_SHA256_DIGEST_LEN * 2] = '\0';
                printf("       rcv sha256: %s\n", buf);
            }

            result_clear(&res);
            free(plaintext);
        }
    }

    printf("\n=== Summary: %d PASS, %d FAIL ===\n", pass, fail);
    return fail == 0 ? 0 : 1;
}
