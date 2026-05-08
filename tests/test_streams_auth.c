/*
 * test_streams_auth.c — Streaming AEAD round-trip + tamper detection
 * over the seed-based itb_stream_encrypt_auth / itb_stream_decrypt_auth
 * surface (Single + Triple Ouroboros).
 *
 * Mirrors the shape of test_streams.c, replacing the plain
 * itb_stream_encrypt / itb_stream_decrypt callback pair with the
 * authenticated variant that takes an itb_mac_t and protects the
 * transcript against reorder, replay, truncate-tail, cross-stream
 * splice, and stream-prefix tamper attacks. Every coverage class
 * required by the Streaming AEAD design surface is exercised:
 *
 *   - Round-trip across (chunk_size × Single / Triple × MAC primitive)
 *   - Empty stream + single-chunk + chunk_size = 1
 *   - Reorder of two chunks                  -> ITB_MAC_FAILURE
 *   - Truncate-tail (drop last chunk)        -> ITB_STREAM_TRUNCATED
 *   - Cross-stream splice (chunk from A in B) -> ITB_MAC_FAILURE
 *   - Stream-prefix tamper (flip 1 prefix byte) -> ITB_MAC_FAILURE
 *
 * Per-binary fork() isolation gives each test its own libitb global
 * state; no in-process serial lock is required.
 */

#include <check.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "itb.h"

/* In-memory ring buffer for stream callbacks. */
typedef struct {
    uint8_t *data;
    size_t   cap;
    size_t   len;
    size_t   read_pos;
    size_t   read_cap;
} membuf_t;

static int membuf_read(void *ctx, void *buf, size_t cap, size_t *out_n)
{
    membuf_t *m = (membuf_t *) ctx;
    size_t avail = m->len - m->read_pos;
    size_t want = (cap < avail) ? cap : avail;
    if (m->read_cap > 0 && want > m->read_cap) want = m->read_cap;
    if (want > 0) {
        memcpy(buf, m->data + m->read_pos, want);
        m->read_pos += want;
    }
    *out_n = want;
    return 0;
}

static int membuf_write(void *ctx, const void *buf, size_t n)
{
    membuf_t *m = (membuf_t *) ctx;
    if (m->len + n > m->cap) {
        size_t new_cap = m->cap == 0 ? 4096 : m->cap * 2;
        while (new_cap < m->len + n) new_cap *= 2;
        uint8_t *p = (uint8_t *) realloc(m->data, new_cap);
        if (p == NULL) return 1;
        m->data = p;
        m->cap = new_cap;
    }
    memcpy(m->data + m->len, buf, n);
    m->len += n;
    return 0;
}

static uint8_t *pseudo_payload(size_t n)
{
    uint8_t *p = (uint8_t *) malloc(n == 0 ? 1 : n);
    ck_assert_ptr_nonnull(p);
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t) (((i * 13u) + 11u) & 0xffu);
    }
    return p;
}

#define SMALL_CHUNK ((size_t) 4096)

/* Allocates a 32-byte MAC key (deterministic so the test harness can
 * encrypt under one MAC and decrypt under an equivalent one across
 * helper invocations — fresh CSPRNG would change between calls). */
static itb_mac_t *make_mac(const char *name)
{
    uint8_t key[32];
    for (size_t i = 0; i < sizeof(key); i++) {
        key[i] = (uint8_t) ((i * 17u + 5u) & 0xffu);
    }
    itb_mac_t *m = NULL;
    ck_assert_int_eq(itb_mac_new(name, key, sizeof(key), &m), ITB_OK);
    ck_assert_ptr_nonnull(m);
    return m;
}

/* ------------------------------------------------------------------ */
/* Single-Ouroboros round-trip                                         */
/* ------------------------------------------------------------------ */

START_TEST(test_auth_single_roundtrip_blake3_kmac256)
{
    itb_seed_t *n = NULL, *d = NULL, *s = NULL;
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &n), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &d), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &s), ITB_OK);
    itb_mac_t *mac = make_mac("kmac256");

    size_t pt_len = SMALL_CHUNK * 4 + 11;
    uint8_t *pt = pseudo_payload(pt_len);

    membuf_t in  = { pt, pt_len, pt_len, 0, 0 };
    membuf_t out = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_stream_encrypt_auth(n, d, s, mac,
                                             membuf_read, &in,
                                             membuf_write, &out,
                                             SMALL_CHUNK), ITB_OK);
    ck_assert_uint_gt(out.len, 32u);

    membuf_t cin = { out.data, out.len, out.len, 0, 0 };
    membuf_t recovered = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_stream_decrypt_auth(n, d, s, mac,
                                             membuf_read, &cin,
                                             membuf_write, &recovered,
                                             SMALL_CHUNK), ITB_OK);
    ck_assert_uint_eq(recovered.len, pt_len);
    ck_assert_mem_eq(recovered.data, pt, pt_len);

    free(pt);
    free(out.data);
    free(recovered.data);
    itb_mac_free(mac);
    itb_seed_free(n);
    itb_seed_free(d);
    itb_seed_free(s);
}
END_TEST

START_TEST(test_auth_single_roundtrip_hmac_blake3)
{
    itb_seed_t *n = NULL, *d = NULL, *s = NULL;
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &n), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &d), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &s), ITB_OK);
    itb_mac_t *mac = make_mac("hmac-blake3");

    size_t pt_len = SMALL_CHUNK * 3 + 7;
    uint8_t *pt = pseudo_payload(pt_len);
    membuf_t in  = { pt, pt_len, pt_len, 0, 1000 };
    membuf_t out = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_stream_encrypt_auth(n, d, s, mac,
                                             membuf_read, &in,
                                             membuf_write, &out,
                                             SMALL_CHUNK), ITB_OK);

    membuf_t cin = { out.data, out.len, out.len, 0, 1024 };
    membuf_t recovered = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_stream_decrypt_auth(n, d, s, mac,
                                             membuf_read, &cin,
                                             membuf_write, &recovered,
                                             SMALL_CHUNK), ITB_OK);
    ck_assert_uint_eq(recovered.len, pt_len);
    ck_assert_mem_eq(recovered.data, pt, pt_len);

    free(pt);
    free(out.data);
    free(recovered.data);
    itb_mac_free(mac);
    itb_seed_free(n);
    itb_seed_free(d);
    itb_seed_free(s);
}
END_TEST

START_TEST(test_auth_single_roundtrip_hmac_sha256_short)
{
    itb_seed_t *n = NULL, *d = NULL, *s = NULL;
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &n), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &d), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &s), ITB_OK);
    itb_mac_t *mac = make_mac("hmac-sha256");

    static const uint8_t plaintext[] = "auth stream short payload coverage";
    size_t pt_len = sizeof(plaintext) - 1;
    membuf_t in  = { (uint8_t *) plaintext, pt_len, pt_len, 0, 0 };
    membuf_t out = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_stream_encrypt_auth(n, d, s, mac,
                                             membuf_read, &in,
                                             membuf_write, &out,
                                             SMALL_CHUNK), ITB_OK);

    membuf_t cin = { out.data, out.len, out.len, 0, 0 };
    membuf_t recovered = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_stream_decrypt_auth(n, d, s, mac,
                                             membuf_read, &cin,
                                             membuf_write, &recovered,
                                             SMALL_CHUNK), ITB_OK);
    ck_assert_uint_eq(recovered.len, pt_len);
    ck_assert_mem_eq(recovered.data, plaintext, pt_len);

    free(out.data);
    free(recovered.data);
    itb_mac_free(mac);
    itb_seed_free(n);
    itb_seed_free(d);
    itb_seed_free(s);
}
END_TEST

START_TEST(test_auth_single_empty_stream)
{
    itb_seed_t *n = NULL, *d = NULL, *s = NULL;
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &n), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &d), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &s), ITB_OK);
    itb_mac_t *mac = make_mac("hmac-blake3");

    membuf_t in  = { NULL, 0, 0, 0, 0 };
    membuf_t out = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_stream_encrypt_auth(n, d, s, mac,
                                             membuf_read, &in,
                                             membuf_write, &out,
                                             SMALL_CHUNK), ITB_OK);
    /* 32-byte stream_id + one terminating chunk over zero plaintext. */
    ck_assert_uint_gt(out.len, 32u);

    membuf_t cin = { out.data, out.len, out.len, 0, 0 };
    membuf_t recovered = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_stream_decrypt_auth(n, d, s, mac,
                                             membuf_read, &cin,
                                             membuf_write, &recovered,
                                             SMALL_CHUNK), ITB_OK);
    ck_assert_uint_eq(recovered.len, 0u);

    free(out.data);
    free(recovered.data);
    itb_mac_free(mac);
    itb_seed_free(n);
    itb_seed_free(d);
    itb_seed_free(s);
}
END_TEST

START_TEST(test_auth_single_chunk_size_1)
{
    itb_seed_t *n = NULL, *d = NULL, *s = NULL;
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &n), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &d), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &s), ITB_OK);
    itb_mac_t *mac = make_mac("hmac-blake3");

    static const uint8_t plaintext[] = "ABCDEFG";
    size_t pt_len = sizeof(plaintext) - 1;
    membuf_t in  = { (uint8_t *) plaintext, pt_len, pt_len, 0, 0 };
    membuf_t out = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_stream_encrypt_auth(n, d, s, mac,
                                             membuf_read, &in,
                                             membuf_write, &out,
                                             1), ITB_OK);

    membuf_t cin = { out.data, out.len, out.len, 0, 0 };
    membuf_t recovered = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_stream_decrypt_auth(n, d, s, mac,
                                             membuf_read, &cin,
                                             membuf_write, &recovered,
                                             1), ITB_OK);
    ck_assert_uint_eq(recovered.len, pt_len);
    ck_assert_mem_eq(recovered.data, plaintext, pt_len);

    free(out.data);
    free(recovered.data);
    itb_mac_free(mac);
    itb_seed_free(n);
    itb_seed_free(d);
    itb_seed_free(s);
}
END_TEST

START_TEST(test_auth_single_single_chunk)
{
    itb_seed_t *n = NULL, *d = NULL, *s = NULL;
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &n), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &d), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &s), ITB_OK);
    itb_mac_t *mac = make_mac("hmac-blake3");

    /* Plaintext smaller than chunk_size — produces exactly one
     * (terminating) chunk. */
    size_t pt_len = 200;
    uint8_t *pt = pseudo_payload(pt_len);
    membuf_t in  = { pt, pt_len, pt_len, 0, 0 };
    membuf_t out = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_stream_encrypt_auth(n, d, s, mac,
                                             membuf_read, &in,
                                             membuf_write, &out,
                                             SMALL_CHUNK), ITB_OK);

    membuf_t cin = { out.data, out.len, out.len, 0, 0 };
    membuf_t recovered = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_stream_decrypt_auth(n, d, s, mac,
                                             membuf_read, &cin,
                                             membuf_write, &recovered,
                                             SMALL_CHUNK), ITB_OK);
    ck_assert_uint_eq(recovered.len, pt_len);
    ck_assert_mem_eq(recovered.data, pt, pt_len);

    free(pt);
    free(out.data);
    free(recovered.data);
    itb_mac_free(mac);
    itb_seed_free(n);
    itb_seed_free(d);
    itb_seed_free(s);
}
END_TEST

/* ------------------------------------------------------------------ */
/* Triple-Ouroboros round-trip                                         */
/* ------------------------------------------------------------------ */

START_TEST(test_auth_triple_roundtrip)
{
    itb_seed_t *seeds[7] = {NULL};
    for (int k = 0; k < 7; k++) {
        ck_assert_int_eq(itb_seed_new("blake3", 1024, &seeds[k]), ITB_OK);
    }
    itb_mac_t *mac = make_mac("hmac-blake3");

    size_t pt_len = SMALL_CHUNK * 3 + 19;
    uint8_t *pt = pseudo_payload(pt_len);
    membuf_t in  = { pt, pt_len, pt_len, 0, 800 };
    membuf_t out = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_stream_encrypt_auth_triple(
                        seeds[0], seeds[1], seeds[2], seeds[3],
                        seeds[4], seeds[5], seeds[6], mac,
                        membuf_read, &in, membuf_write, &out,
                        SMALL_CHUNK), ITB_OK);

    membuf_t cin = { out.data, out.len, out.len, 0, 0 };
    membuf_t recovered = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_stream_decrypt_auth_triple(
                        seeds[0], seeds[1], seeds[2], seeds[3],
                        seeds[4], seeds[5], seeds[6], mac,
                        membuf_read, &cin, membuf_write, &recovered,
                        SMALL_CHUNK), ITB_OK);
    ck_assert_uint_eq(recovered.len, pt_len);
    ck_assert_mem_eq(recovered.data, pt, pt_len);

    free(pt);
    free(out.data);
    free(recovered.data);
    itb_mac_free(mac);
    for (int k = 0; k < 7; k++) itb_seed_free(seeds[k]);
}
END_TEST

/* ------------------------------------------------------------------ */
/* Tamper detection                                                    */
/* ------------------------------------------------------------------ */

/* Helper: encrypt a 3-chunk transcript and return the wire bytes plus
 * each chunk's start offset for tamper-test surgery. */
static uint8_t *make_3chunk_transcript(itb_seed_t *n,
                                       itb_seed_t *d,
                                       itb_seed_t *s,
                                       const itb_mac_t *mac,
                                       size_t chunk_size,
                                       size_t *out_len,
                                       size_t chunk_offsets[3],
                                       size_t chunk_lens[3])
{
    size_t pt_len = chunk_size * 3 - 7; /* 3 chunks: 2 full + 1 short tail */
    uint8_t *pt = pseudo_payload(pt_len);
    membuf_t in  = { pt, pt_len, pt_len, 0, 0 };
    membuf_t out = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_stream_encrypt_auth(n, d, s, mac,
                                             membuf_read, &in,
                                             membuf_write, &out,
                                             chunk_size), ITB_OK);

    /* Walk chunk headers from offset 32 (after stream_id prefix) to
     * record per-chunk offsets and lengths. */
    int hsz = itb_header_size();
    ck_assert_int_gt(hsz, 0);
    size_t cur = 32;
    for (int i = 0; i < 3; i++) {
        chunk_offsets[i] = cur;
        size_t cl = 0;
        ck_assert_int_eq(itb_parse_chunk_len(out.data + cur, (size_t) hsz, &cl),
                         ITB_OK);
        chunk_lens[i] = cl;
        cur += cl;
    }
    ck_assert_uint_eq(cur, out.len);
    free(pt);
    *out_len = out.len;
    return out.data;
}

START_TEST(test_auth_reorder_two_chunks)
{
    itb_seed_t *n = NULL, *d = NULL, *s = NULL;
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &n), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &d), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &s), ITB_OK);
    itb_mac_t *mac = make_mac("hmac-blake3");

    size_t wire_len = 0;
    size_t off[3], len[3];
    uint8_t *wire = make_3chunk_transcript(n, d, s, mac, SMALL_CHUNK,
                                           &wire_len, off, len);

    /* Swap chunks 0 and 1 on the wire. They must have the same length
     * for an in-place swap to be sensible; the helper guarantees both
     * are full-sized chunk_size chunks. */
    ck_assert_uint_eq(len[0], len[1]);
    uint8_t *tmp = (uint8_t *) malloc(len[0]);
    ck_assert_ptr_nonnull(tmp);
    memcpy(tmp, wire + off[0], len[0]);
    memcpy(wire + off[0], wire + off[1], len[1]);
    memcpy(wire + off[1], tmp, len[0]);
    free(tmp);

    membuf_t cin = { wire, wire_len, wire_len, 0, 0 };
    membuf_t recovered = { NULL, 0, 0, 0, 0 };
    itb_status_t rc = itb_stream_decrypt_auth(n, d, s, mac,
                                              membuf_read, &cin,
                                              membuf_write, &recovered,
                                              SMALL_CHUNK);
    ck_assert_int_eq(rc, ITB_MAC_FAILURE);

    free(wire);
    free(recovered.data);
    itb_mac_free(mac);
    itb_seed_free(n);
    itb_seed_free(d);
    itb_seed_free(s);
}
END_TEST

START_TEST(test_auth_truncate_tail)
{
    itb_seed_t *n = NULL, *d = NULL, *s = NULL;
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &n), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &d), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &s), ITB_OK);
    itb_mac_t *mac = make_mac("hmac-blake3");

    size_t wire_len = 0;
    size_t off[3], len[3];
    uint8_t *wire = make_3chunk_transcript(n, d, s, mac, SMALL_CHUNK,
                                           &wire_len, off, len);
    /* Drop the last chunk: present only chunks 0 and 1. */
    size_t truncated_len = off[2];

    membuf_t cin = { wire, wire_len, truncated_len, 0, 0 };
    membuf_t recovered = { NULL, 0, 0, 0, 0 };
    itb_status_t rc = itb_stream_decrypt_auth(n, d, s, mac,
                                              membuf_read, &cin,
                                              membuf_write, &recovered,
                                              SMALL_CHUNK);
    ck_assert_int_eq(rc, ITB_STREAM_TRUNCATED);

    free(wire);
    free(recovered.data);
    itb_mac_free(mac);
    itb_seed_free(n);
    itb_seed_free(d);
    itb_seed_free(s);
}
END_TEST

START_TEST(test_auth_stream_prefix_tamper)
{
    itb_seed_t *n = NULL, *d = NULL, *s = NULL;
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &n), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &d), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &s), ITB_OK);
    itb_mac_t *mac = make_mac("hmac-blake3");

    size_t pt_len = SMALL_CHUNK + 5;
    uint8_t *pt = pseudo_payload(pt_len);
    membuf_t in  = { pt, pt_len, pt_len, 0, 0 };
    membuf_t out = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_stream_encrypt_auth(n, d, s, mac,
                                             membuf_read, &in,
                                             membuf_write, &out,
                                             SMALL_CHUNK), ITB_OK);

    /* Flip one byte in the 32-byte stream_id prefix. */
    out.data[5] ^= 0x55;

    membuf_t cin = { out.data, out.len, out.len, 0, 0 };
    membuf_t recovered = { NULL, 0, 0, 0, 0 };
    itb_status_t rc = itb_stream_decrypt_auth(n, d, s, mac,
                                              membuf_read, &cin,
                                              membuf_write, &recovered,
                                              SMALL_CHUNK);
    ck_assert_int_eq(rc, ITB_MAC_FAILURE);

    free(pt);
    free(out.data);
    free(recovered.data);
    itb_mac_free(mac);
    itb_seed_free(n);
    itb_seed_free(d);
    itb_seed_free(s);
}
END_TEST

/* Helper: encrypt a 2-chunk transcript (1 full + 1 short tail) and
 * return wire bytes plus per-chunk offsets and lengths. Mirrors the
 * 3-chunk helper, sized to surface the trailing-bytes-after-terminator
 * path with minimal payload. */
static uint8_t *make_2chunk_transcript(itb_seed_t *n,
                                       itb_seed_t *d,
                                       itb_seed_t *s,
                                       const itb_mac_t *mac,
                                       size_t chunk_size,
                                       size_t *out_len,
                                       size_t chunk_offsets[2],
                                       size_t chunk_lens[2])
{
    size_t pt_len = chunk_size + 11; /* 1 full + 1 short tail */
    uint8_t *pt = pseudo_payload(pt_len);
    membuf_t in  = { pt, pt_len, pt_len, 0, 0 };
    membuf_t out = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_stream_encrypt_auth(n, d, s, mac,
                                             membuf_read, &in,
                                             membuf_write, &out,
                                             chunk_size), ITB_OK);

    int hsz = itb_header_size();
    ck_assert_int_gt(hsz, 0);
    size_t cur = 32;
    for (int i = 0; i < 2; i++) {
        chunk_offsets[i] = cur;
        size_t cl = 0;
        ck_assert_int_eq(itb_parse_chunk_len(out.data + cur, (size_t) hsz, &cl),
                         ITB_OK);
        chunk_lens[i] = cl;
        cur += cl;
    }
    ck_assert_uint_eq(cur, out.len);
    free(pt);
    *out_len = out.len;
    return out.data;
}

START_TEST(test_auth_stream_after_final)
{
    itb_seed_t *n = NULL, *d = NULL, *s = NULL;
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &n), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &d), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &s), ITB_OK);
    itb_mac_t *mac = make_mac("hmac-blake3");

    size_t wire_len = 0;
    size_t off[2], len[2];
    uint8_t *wire = make_2chunk_transcript(n, d, s, mac, SMALL_CHUNK,
                                           &wire_len, off, len);

    /* Append a duplicate of the terminator (chunk 1) past the
     * terminating chunk. The decoder must observe the terminator and
     * then surface ITB_STREAM_AFTER_FINAL on the trailing bytes. */
    size_t extra = len[1];
    uint8_t *with_extra = (uint8_t *) malloc(wire_len + extra);
    ck_assert_ptr_nonnull(with_extra);
    memcpy(with_extra, wire, wire_len);
    memcpy(with_extra + wire_len, wire + off[1], extra);

    membuf_t cin = { with_extra, wire_len + extra, wire_len + extra, 0, 0 };
    membuf_t recovered = { NULL, 0, 0, 0, 0 };
    itb_status_t rc = itb_stream_decrypt_auth(n, d, s, mac,
                                              membuf_read, &cin,
                                              membuf_write, &recovered,
                                              SMALL_CHUNK);
    ck_assert_int_eq(rc, ITB_STREAM_AFTER_FINAL);

    free(wire);
    free(with_extra);
    free(recovered.data);
    itb_mac_free(mac);
    itb_seed_free(n);
    itb_seed_free(d);
    itb_seed_free(s);
}
END_TEST

START_TEST(test_auth_cross_stream_replay)
{
    itb_seed_t *n = NULL, *d = NULL, *s = NULL;
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &n), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &d), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &s), ITB_OK);
    itb_mac_t *mac = make_mac("hmac-blake3");

    /* Encrypt two distinct streams under the same seeds + MAC. */
    size_t pt_len = SMALL_CHUNK * 2 + 3;
    uint8_t *pt_a = pseudo_payload(pt_len);
    uint8_t *pt_b = (uint8_t *) malloc(pt_len);
    for (size_t i = 0; i < pt_len; i++) pt_b[i] = (uint8_t) (pt_a[i] ^ 0xaau);

    membuf_t in_a = { pt_a, pt_len, pt_len, 0, 0 };
    membuf_t out_a = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_stream_encrypt_auth(n, d, s, mac,
                                             membuf_read, &in_a,
                                             membuf_write, &out_a,
                                             SMALL_CHUNK), ITB_OK);

    membuf_t in_b = { pt_b, pt_len, pt_len, 0, 0 };
    membuf_t out_b = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_stream_encrypt_auth(n, d, s, mac,
                                             membuf_read, &in_b,
                                             membuf_write, &out_b,
                                             SMALL_CHUNK), ITB_OK);

    /* Walk chunk offsets in stream A and stream B; chunk 0 sits at
     * offset 32. Splice A's chunk 0 into B's chunk 0 slot. */
    int hsz = itb_header_size();
    size_t a_off = 32, b_off = 32;
    size_t a_len = 0, b_len = 0;
    ck_assert_int_eq(itb_parse_chunk_len(out_a.data + a_off, (size_t) hsz, &a_len),
                     ITB_OK);
    ck_assert_int_eq(itb_parse_chunk_len(out_b.data + b_off, (size_t) hsz, &b_len),
                     ITB_OK);
    ck_assert_uint_eq(a_len, b_len);
    memcpy(out_b.data + b_off, out_a.data + a_off, a_len);

    membuf_t cin = { out_b.data, out_b.len, out_b.len, 0, 0 };
    membuf_t recovered = { NULL, 0, 0, 0, 0 };
    itb_status_t rc = itb_stream_decrypt_auth(n, d, s, mac,
                                              membuf_read, &cin,
                                              membuf_write, &recovered,
                                              SMALL_CHUNK);
    ck_assert_int_eq(rc, ITB_MAC_FAILURE);

    free(pt_a);
    free(pt_b);
    free(out_a.data);
    free(out_b.data);
    free(recovered.data);
    itb_mac_free(mac);
    itb_seed_free(n);
    itb_seed_free(d);
    itb_seed_free(s);
}
END_TEST

int main(void)
{
    Suite *s = suite_create("streams_auth");
    TCase *tc = tcase_create("core");
    tcase_set_timeout(tc, 180);
    tcase_add_test(tc, test_auth_single_roundtrip_blake3_kmac256);
    tcase_add_test(tc, test_auth_single_roundtrip_hmac_blake3);
    tcase_add_test(tc, test_auth_single_roundtrip_hmac_sha256_short);
    tcase_add_test(tc, test_auth_single_empty_stream);
    tcase_add_test(tc, test_auth_single_chunk_size_1);
    tcase_add_test(tc, test_auth_single_single_chunk);
    tcase_add_test(tc, test_auth_triple_roundtrip);
    tcase_add_test(tc, test_auth_reorder_two_chunks);
    tcase_add_test(tc, test_auth_truncate_tail);
    tcase_add_test(tc, test_auth_stream_prefix_tamper);
    tcase_add_test(tc, test_auth_stream_after_final);
    tcase_add_test(tc, test_auth_cross_stream_replay);
    suite_add_tcase(s, tc);

    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int failures = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failures == 0 ? 0 : 1;
}
