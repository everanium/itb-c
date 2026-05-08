/*
 * test_easy_streams.c — streaming-style use of the high-level
 * Encryptor surface.
 *
 * Mirrors bindings/rust/tests/test_easy_streams.rs one-to-one. The Easy
 * API does NOT expose dedicated stream helpers — streaming over the
 * Encryptor lives entirely on the binding-side: the consumer slices
 * plaintext into chunks of the desired size and calls
 * itb_encryptor_encrypt per chunk; the decrypt side walks the
 * concatenated chunk stream by reading itb_encryptor_header_size bytes,
 * calling itb_encryptor_parse_chunk_len, reading the remaining body,
 * and feeding the full chunk to itb_encryptor_decrypt.
 *
 * This file therefore differs from test_streams.c (Phase 5B), which
 * exercises the seed-based itb_stream_encrypt / itb_stream_decrypt
 * surface. The two surfaces are independent: test_streams.c covers the
 * one-shot read_fn / write_fn callback pair; this file covers the
 * Encryptor-driven chunk loop. Triple-Ouroboros (mode=3) and
 * non-default nonce-bits configurations are covered explicitly so a
 * regression in itb_encryptor_header_size / itb_encryptor_parse_chunk_len
 * surfaces here.
 *
 * Per-binary fork() isolation gives this test its own libitb global
 * state, so no in-process serial lock is required.
 */

#include <check.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "itb.h"

#define SMALL_CHUNK ((size_t) 4096)

static uint8_t *token_bytes(size_t n) {
    static uint64_t ctr = 0x123456789ABCDEF0ULL;
    ctr += 0x9E3779B97F4A7C15ULL;
    uint64_t state = ctr ^ ((uint64_t)(uintptr_t)&ctr);
    uint8_t *out = (uint8_t *)malloc(n == 0 ? 1 : n);
    ck_assert_ptr_nonnull(out);
    for (size_t i = 0; i < n; i++) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        out[i] = (uint8_t)(state >> 33);
    }
    return out;
}

/* Encrypts plaintext chunk-by-chunk through enc.encrypt and returns
 * the concatenated ciphertext stream (caller frees with free()). */
static uint8_t *stream_encrypt(itb_encryptor_t *enc,
                               const uint8_t *plaintext, size_t plaintext_len,
                               size_t chunk_size, size_t *out_len)
{
    size_t cap = plaintext_len + plaintext_len / 4 + 64;
    if (cap < 64) cap = 64;
    uint8_t *out = (uint8_t *)malloc(cap);
    ck_assert_ptr_nonnull(out);
    size_t out_used = 0;

    size_t i = 0;
    while (i < plaintext_len) {
        size_t end = i + chunk_size;
        if (end > plaintext_len) end = plaintext_len;
        uint8_t *ct = NULL; size_t ct_len = 0;
        ck_assert_int_eq(itb_encryptor_encrypt(enc, plaintext + i, end - i,
                                               &ct, &ct_len), ITB_OK);
        if (out_used + ct_len > cap) {
            while (out_used + ct_len > cap) cap *= 2;
            uint8_t *p = (uint8_t *)realloc(out, cap);
            ck_assert_ptr_nonnull(p);
            out = p;
        }
        memcpy(out + out_used, ct, ct_len);
        out_used += ct_len;
        itb_buffer_free(ct);
        i = end;
    }
    *out_len = out_used;
    return out;
}

/* Drains the concatenated ciphertext stream chunk-by-chunk and returns
 * the recovered plaintext (caller frees with free()). Returns NULL on
 * a trailing incomplete chunk so the test harness can assert the
 * plausible-failure contract; *out_len set to 0 on that failure. */
static uint8_t *stream_decrypt(itb_encryptor_t *enc,
                               const uint8_t *ciphertext, size_t ciphertext_len,
                               size_t *out_len, int *out_trailing)
{
    *out_trailing = 0;
    int hsize = 0;
    ck_assert_int_eq(itb_encryptor_header_size(enc, &hsize), ITB_OK);
    size_t header_size = (size_t)hsize;

    size_t out_cap = ciphertext_len + 64;
    uint8_t *out = (uint8_t *)malloc(out_cap);
    ck_assert_ptr_nonnull(out);
    size_t out_used = 0;

    /* Accumulator: copy the ciphertext incrementally in SMALL_CHUNK
     * shards and drain whole chunks as soon as parse_chunk_len reports
     * a complete one. */
    size_t acc_cap = SMALL_CHUNK * 2 + 64;
    uint8_t *acc = (uint8_t *)malloc(acc_cap);
    ck_assert_ptr_nonnull(acc);
    size_t acc_len = 0;

    size_t feed_off = 0;
    while (feed_off < ciphertext_len) {
        size_t end = feed_off + SMALL_CHUNK;
        if (end > ciphertext_len) end = ciphertext_len;
        size_t chunk_in = end - feed_off;
        if (acc_len + chunk_in > acc_cap) {
            while (acc_len + chunk_in > acc_cap) acc_cap *= 2;
            uint8_t *p = (uint8_t *)realloc(acc, acc_cap);
            ck_assert_ptr_nonnull(p);
            acc = p;
        }
        memcpy(acc + acc_len, ciphertext + feed_off, chunk_in);
        acc_len += chunk_in;
        feed_off = end;

        /* Drain whole chunks. */
        for (;;) {
            if (acc_len < header_size) break;
            size_t chunk_len = 0;
            itb_status_t rc = itb_encryptor_parse_chunk_len(enc, acc, header_size,
                                                            &chunk_len);
            ck_assert_int_eq(rc, ITB_OK);
            if (acc_len < chunk_len) break;
            uint8_t *pt = NULL; size_t pt_len = 0;
            ck_assert_int_eq(itb_encryptor_decrypt(enc, acc, chunk_len,
                                                   &pt, &pt_len), ITB_OK);
            if (out_used + pt_len > out_cap) {
                while (out_used + pt_len > out_cap) out_cap *= 2;
                uint8_t *p = (uint8_t *)realloc(out, out_cap);
                ck_assert_ptr_nonnull(p);
                out = p;
            }
            memcpy(out + out_used, pt, pt_len);
            out_used += pt_len;
            itb_buffer_free(pt);
            /* Drain chunk_len bytes from the accumulator front. */
            memmove(acc, acc + chunk_len, acc_len - chunk_len);
            acc_len -= chunk_len;
        }
    }

    if (acc_len != 0) {
        free(out);
        free(acc);
        *out_len = 0;
        *out_trailing = 1;
        return NULL;
    }
    free(acc);
    *out_len = out_used;
    return out;
}

START_TEST(test_easy_streams_roundtrip_default_nonce_single)
{
    size_t pt_len = SMALL_CHUNK * 5 + 17;
    uint8_t *plaintext = token_bytes(pt_len);

    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &enc), ITB_OK);

    size_t ct_len = 0;
    uint8_t *ct = stream_encrypt(enc, plaintext, pt_len, SMALL_CHUNK, &ct_len);
    int trailing = 0;
    size_t recovered_len = 0;
    uint8_t *recovered = stream_decrypt(enc, ct, ct_len, &recovered_len, &trailing);
    ck_assert_int_eq(trailing, 0);
    ck_assert_uint_eq(recovered_len, pt_len);
    ck_assert_mem_eq(recovered, plaintext, pt_len);

    free(plaintext);
    free(ct);
    free(recovered);
    itb_encryptor_free(enc);
}
END_TEST

START_TEST(test_easy_streams_roundtrip_non_default_nonce_single)
{
    size_t pt_len = SMALL_CHUNK * 3 + 100;
    uint8_t *plaintext = token_bytes(pt_len);
    static const int NONCES[] = {256, 512};
    for (size_t i = 0; i < sizeof(NONCES) / sizeof(NONCES[0]); i++) {
        itb_encryptor_t *enc = NULL;
        ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &enc), ITB_OK);
        ck_assert_int_eq(itb_encryptor_set_nonce_bits(enc, NONCES[i]), ITB_OK);

        size_t ct_len = 0;
        uint8_t *ct = stream_encrypt(enc, plaintext, pt_len, SMALL_CHUNK, &ct_len);
        int trailing = 0;
        size_t recovered_len = 0;
        uint8_t *recovered = stream_decrypt(enc, ct, ct_len, &recovered_len, &trailing);
        ck_assert_int_eq(trailing, 0);
        ck_assert_uint_eq(recovered_len, pt_len);
        ck_assert_mem_eq(recovered, plaintext, pt_len);

        free(ct);
        free(recovered);
        itb_encryptor_free(enc);
    }
    free(plaintext);
}
END_TEST

START_TEST(test_easy_streams_triple_roundtrip_default_nonce)
{
    size_t pt_len = SMALL_CHUNK * 4 + 33;
    uint8_t *plaintext = token_bytes(pt_len);

    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 3, &enc), ITB_OK);

    size_t ct_len = 0;
    uint8_t *ct = stream_encrypt(enc, plaintext, pt_len, SMALL_CHUNK, &ct_len);
    int trailing = 0;
    size_t recovered_len = 0;
    uint8_t *recovered = stream_decrypt(enc, ct, ct_len, &recovered_len, &trailing);
    ck_assert_int_eq(trailing, 0);
    ck_assert_uint_eq(recovered_len, pt_len);
    ck_assert_mem_eq(recovered, plaintext, pt_len);

    free(plaintext);
    free(ct);
    free(recovered);
    itb_encryptor_free(enc);
}
END_TEST

START_TEST(test_easy_streams_triple_roundtrip_non_default_nonce)
{
    size_t pt_len = SMALL_CHUNK * 3;
    uint8_t *plaintext = token_bytes(pt_len);
    static const int NONCES[] = {256, 512};
    for (size_t i = 0; i < sizeof(NONCES) / sizeof(NONCES[0]); i++) {
        itb_encryptor_t *enc = NULL;
        ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 3, &enc), ITB_OK);
        ck_assert_int_eq(itb_encryptor_set_nonce_bits(enc, NONCES[i]), ITB_OK);

        size_t ct_len = 0;
        uint8_t *ct = stream_encrypt(enc, plaintext, pt_len, SMALL_CHUNK, &ct_len);
        int trailing = 0;
        size_t recovered_len = 0;
        uint8_t *recovered = stream_decrypt(enc, ct, ct_len, &recovered_len, &trailing);
        ck_assert_int_eq(trailing, 0);
        ck_assert_uint_eq(recovered_len, pt_len);
        ck_assert_mem_eq(recovered, plaintext, pt_len);

        free(ct);
        free(recovered);
        itb_encryptor_free(enc);
    }
    free(plaintext);
}
END_TEST

START_TEST(test_easy_streams_partial_chunk_raises)
{
    /* Feeding only a partial chunk to the streaming decoder surfaces
     * a trailing-bytes failure on close. */
    size_t pt_len = 100;
    uint8_t *plaintext = (uint8_t *)malloc(pt_len);
    ck_assert_ptr_nonnull(plaintext);
    memset(plaintext, 'x', pt_len);

    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &enc), ITB_OK);

    size_t ct_len = 0;
    uint8_t *ct = stream_encrypt(enc, plaintext, pt_len, SMALL_CHUNK, &ct_len);
    /* Feed only 30 bytes — header complete (>= 20) but body truncated.
     * The drain loop must reject the trailing incomplete chunk. */
    int trailing = 0;
    size_t recovered_len = 0;
    uint8_t *recovered = stream_decrypt(enc, ct, 30, &recovered_len, &trailing);
    ck_assert_int_eq(trailing, 1);
    ck_assert_ptr_null(recovered);

    free(plaintext);
    free(ct);
    itb_encryptor_free(enc);
}
END_TEST

START_TEST(test_easy_streams_parse_chunk_len_short_buffer)
{
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &enc), ITB_OK);
    int hs = 0;
    ck_assert_int_eq(itb_encryptor_header_size(enc, &hs), ITB_OK);
    size_t cap = (size_t)hs - 1;
    uint8_t *buf = (uint8_t *)calloc(cap, 1);
    ck_assert_ptr_nonnull(buf);

    size_t parsed = 0;
    ck_assert_int_eq(itb_encryptor_parse_chunk_len(enc, buf, cap, &parsed), ITB_BAD_INPUT);

    free(buf);
    itb_encryptor_free(enc);
}
END_TEST

START_TEST(test_easy_streams_parse_chunk_len_zero_dim)
{
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &enc), ITB_OK);
    int hs = 0;
    ck_assert_int_eq(itb_encryptor_header_size(enc, &hs), ITB_OK);
    /* header_size bytes, all zero — width == 0 → reject. */
    uint8_t *hdr = (uint8_t *)calloc((size_t)hs, 1);
    ck_assert_ptr_nonnull(hdr);
    size_t parsed = 0;
    ck_assert_int_ne(itb_encryptor_parse_chunk_len(enc, hdr, (size_t)hs, &parsed),
                     ITB_OK);
    free(hdr);
    itb_encryptor_free(enc);
}
END_TEST

int main(void)
{
    Suite *s = suite_create("easy_streams");
    TCase *tc = tcase_create("core");
    tcase_set_timeout(tc, 120);
    tcase_add_test(tc, test_easy_streams_roundtrip_default_nonce_single);
    tcase_add_test(tc, test_easy_streams_roundtrip_non_default_nonce_single);
    tcase_add_test(tc, test_easy_streams_triple_roundtrip_default_nonce);
    tcase_add_test(tc, test_easy_streams_triple_roundtrip_non_default_nonce);
    tcase_add_test(tc, test_easy_streams_partial_chunk_raises);
    tcase_add_test(tc, test_easy_streams_parse_chunk_len_short_buffer);
    tcase_add_test(tc, test_easy_streams_parse_chunk_len_zero_dim);
    suite_add_tcase(s, tc);

    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int failures = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failures == 0 ? 0 : 1;
}
