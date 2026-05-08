/*
 * test_easy_nonce_sizes.c — round-trip tests across every per-instance
 * nonce-size configuration on the high-level Encryptor surface.
 *
 * Mirrors bindings/rust/tests/test_easy_nonce_sizes.rs one-to-one.
 * itb_encryptor_set_nonce_bits is per-instance and does not touch the
 * process-global itb_set_nonce_bits / itb_get_nonce_bits accessors;
 * each encryptor's itb_encryptor_header_size and
 * itb_encryptor_parse_chunk_len track its own nonce_bits state. None of
 * the tests in this file mutate process-global state.
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

static const int NONCE_SIZES[] = {128, 256, 512};
#define NONCE_SIZES_COUNT (sizeof(NONCE_SIZES) / sizeof(NONCE_SIZES[0]))

static const char *HASHES[] = {"siphash24", "blake3", "blake2b512"};
#define HASHES_COUNT (sizeof(HASHES) / sizeof(HASHES[0]))

static const char *MACS[] = {"kmac256", "hmac-sha256", "hmac-blake3"};
#define MACS_COUNT (sizeof(MACS) / sizeof(MACS[0]))

static uint8_t *token_bytes(size_t n) {
    static uint64_t ctr = 0xA5A5A5A55A5A5A5AULL;
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

START_TEST(test_easy_nonce_sizes_header_size_default_is_20)
{
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &enc), ITB_OK);
    int hs = 0;
    ck_assert_int_eq(itb_encryptor_header_size(enc, &hs), ITB_OK);
    ck_assert_int_eq(hs, 20);
    int nb = 0;
    ck_assert_int_eq(itb_encryptor_nonce_bits(enc, &nb), ITB_OK);
    ck_assert_int_eq(nb, 128);
    itb_encryptor_free(enc);
}
END_TEST

START_TEST(test_easy_nonce_sizes_header_size_dynamic)
{
    for (size_t i = 0; i < NONCE_SIZES_COUNT; i++) {
        itb_encryptor_t *enc = NULL;
        ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &enc), ITB_OK);
        ck_assert_int_eq(itb_encryptor_set_nonce_bits(enc, NONCE_SIZES[i]), ITB_OK);
        int nb = 0;
        ck_assert_int_eq(itb_encryptor_nonce_bits(enc, &nb), ITB_OK);
        ck_assert_int_eq(nb, NONCE_SIZES[i]);
        int hs = 0;
        ck_assert_int_eq(itb_encryptor_header_size(enc, &hs), ITB_OK);
        ck_assert_int_eq(hs, NONCE_SIZES[i] / 8 + 4);
        itb_encryptor_free(enc);
    }
}
END_TEST

START_TEST(test_easy_nonce_sizes_encrypt_decrypt_across_single)
{
    size_t pt_len = 1024;
    uint8_t *plaintext = token_bytes(pt_len);

    for (size_t i = 0; i < NONCE_SIZES_COUNT; i++) {
        for (size_t h = 0; h < HASHES_COUNT; h++) {
            itb_encryptor_t *enc = NULL;
            ck_assert_int_eq(itb_encryptor_new(HASHES[h], 1024, "kmac256", 1, &enc), ITB_OK);
            ck_assert_int_eq(itb_encryptor_set_nonce_bits(enc, NONCE_SIZES[i]), ITB_OK);

            uint8_t *ct = NULL; size_t ct_len = 0;
            ck_assert_int_eq(itb_encryptor_encrypt(enc, plaintext, pt_len,
                                                   &ct, &ct_len), ITB_OK);
            uint8_t *pt = NULL; size_t pt_out_len = 0;
            ck_assert_int_eq(itb_encryptor_decrypt(enc, ct, ct_len, &pt, &pt_out_len), ITB_OK);
            ck_assert_uint_eq(pt_out_len, pt_len);
            ck_assert_mem_eq(pt, plaintext, pt_len);

            int hs = 0;
            ck_assert_int_eq(itb_encryptor_header_size(enc, &hs), ITB_OK);
            size_t parsed = 0;
            ck_assert_int_eq(itb_encryptor_parse_chunk_len(enc, ct, (size_t)hs,
                                                           &parsed), ITB_OK);
            ck_assert_uint_eq(parsed, ct_len);

            itb_buffer_free(ct);
            itb_buffer_free(pt);
            itb_encryptor_free(enc);
        }
    }
    free(plaintext);
}
END_TEST

START_TEST(test_easy_nonce_sizes_encrypt_decrypt_across_triple)
{
    size_t pt_len = 1024;
    uint8_t *plaintext = token_bytes(pt_len);

    for (size_t i = 0; i < NONCE_SIZES_COUNT; i++) {
        for (size_t h = 0; h < HASHES_COUNT; h++) {
            itb_encryptor_t *enc = NULL;
            ck_assert_int_eq(itb_encryptor_new(HASHES[h], 1024, "kmac256", 3, &enc), ITB_OK);
            ck_assert_int_eq(itb_encryptor_set_nonce_bits(enc, NONCE_SIZES[i]), ITB_OK);

            uint8_t *ct = NULL; size_t ct_len = 0;
            ck_assert_int_eq(itb_encryptor_encrypt(enc, plaintext, pt_len,
                                                   &ct, &ct_len), ITB_OK);
            uint8_t *pt = NULL; size_t pt_out_len = 0;
            ck_assert_int_eq(itb_encryptor_decrypt(enc, ct, ct_len, &pt, &pt_out_len), ITB_OK);
            ck_assert_uint_eq(pt_out_len, pt_len);
            ck_assert_mem_eq(pt, plaintext, pt_len);

            int hs = 0;
            ck_assert_int_eq(itb_encryptor_header_size(enc, &hs), ITB_OK);
            size_t parsed = 0;
            ck_assert_int_eq(itb_encryptor_parse_chunk_len(enc, ct, (size_t)hs,
                                                           &parsed), ITB_OK);
            ck_assert_uint_eq(parsed, ct_len);

            itb_buffer_free(ct);
            itb_buffer_free(pt);
            itb_encryptor_free(enc);
        }
    }
    free(plaintext);
}
END_TEST

START_TEST(test_easy_nonce_sizes_auth_across_single)
{
    size_t pt_len = 1024;
    uint8_t *plaintext = token_bytes(pt_len);

    for (size_t i = 0; i < NONCE_SIZES_COUNT; i++) {
        for (size_t m = 0; m < MACS_COUNT; m++) {
            itb_encryptor_t *enc = NULL;
            ck_assert_int_eq(itb_encryptor_new("blake3", 1024, MACS[m], 1, &enc), ITB_OK);
            ck_assert_int_eq(itb_encryptor_set_nonce_bits(enc, NONCE_SIZES[i]), ITB_OK);

            uint8_t *ct = NULL; size_t ct_len = 0;
            ck_assert_int_eq(itb_encryptor_encrypt_auth(enc, plaintext, pt_len,
                                                        &ct, &ct_len), ITB_OK);
            uint8_t *pt = NULL; size_t pt_out_len = 0;
            ck_assert_int_eq(itb_encryptor_decrypt_auth(enc, ct, ct_len,
                                                        &pt, &pt_out_len), ITB_OK);
            ck_assert_uint_eq(pt_out_len, pt_len);
            ck_assert_mem_eq(pt, plaintext, pt_len);

            int hs = 0;
            ck_assert_int_eq(itb_encryptor_header_size(enc, &hs), ITB_OK);
            size_t end = (size_t)hs + 256;
            if (end > ct_len) end = ct_len;
            for (size_t b = (size_t)hs; b < end; b++) {
                ct[b] ^= 0x01;
            }
            uint8_t *bad = NULL; size_t bad_len = 0;
            ck_assert_int_eq(itb_encryptor_decrypt_auth(enc, ct, ct_len, &bad, &bad_len),
                             ITB_MAC_FAILURE);
            ck_assert_ptr_null(bad);

            itb_buffer_free(ct);
            itb_buffer_free(pt);
            itb_encryptor_free(enc);
        }
    }
    free(plaintext);
}
END_TEST

START_TEST(test_easy_nonce_sizes_auth_across_triple)
{
    size_t pt_len = 1024;
    uint8_t *plaintext = token_bytes(pt_len);

    for (size_t i = 0; i < NONCE_SIZES_COUNT; i++) {
        for (size_t m = 0; m < MACS_COUNT; m++) {
            itb_encryptor_t *enc = NULL;
            ck_assert_int_eq(itb_encryptor_new("blake3", 1024, MACS[m], 3, &enc), ITB_OK);
            ck_assert_int_eq(itb_encryptor_set_nonce_bits(enc, NONCE_SIZES[i]), ITB_OK);

            uint8_t *ct = NULL; size_t ct_len = 0;
            ck_assert_int_eq(itb_encryptor_encrypt_auth(enc, plaintext, pt_len,
                                                        &ct, &ct_len), ITB_OK);
            uint8_t *pt = NULL; size_t pt_out_len = 0;
            ck_assert_int_eq(itb_encryptor_decrypt_auth(enc, ct, ct_len,
                                                        &pt, &pt_out_len), ITB_OK);
            ck_assert_uint_eq(pt_out_len, pt_len);
            ck_assert_mem_eq(pt, plaintext, pt_len);

            int hs = 0;
            ck_assert_int_eq(itb_encryptor_header_size(enc, &hs), ITB_OK);
            size_t end = (size_t)hs + 256;
            if (end > ct_len) end = ct_len;
            for (size_t b = (size_t)hs; b < end; b++) {
                ct[b] ^= 0x01;
            }
            uint8_t *bad = NULL; size_t bad_len = 0;
            ck_assert_int_eq(itb_encryptor_decrypt_auth(enc, ct, ct_len, &bad, &bad_len),
                             ITB_MAC_FAILURE);
            ck_assert_ptr_null(bad);

            itb_buffer_free(ct);
            itb_buffer_free(pt);
            itb_encryptor_free(enc);
        }
    }
    free(plaintext);
}
END_TEST

START_TEST(test_easy_nonce_sizes_two_encryptors_independent_nonce_bits)
{
    static const uint8_t plaintext[] = "isolation test";
    size_t pt_len = sizeof(plaintext) - 1;

    itb_encryptor_t *a = NULL;
    itb_encryptor_t *b = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &a), ITB_OK);
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &b), ITB_OK);

    ck_assert_int_eq(itb_encryptor_set_nonce_bits(a, 512), ITB_OK);

    int nb = 0;
    ck_assert_int_eq(itb_encryptor_nonce_bits(a, &nb), ITB_OK);
    ck_assert_int_eq(nb, 512);
    int hs = 0;
    ck_assert_int_eq(itb_encryptor_header_size(a, &hs), ITB_OK);
    ck_assert_int_eq(hs, 68);

    ck_assert_int_eq(itb_encryptor_nonce_bits(b, &nb), ITB_OK);
    ck_assert_int_eq(nb, 128);
    ck_assert_int_eq(itb_encryptor_header_size(b, &hs), ITB_OK);
    ck_assert_int_eq(hs, 20);

    uint8_t *ct_a = NULL; size_t ct_a_len = 0;
    ck_assert_int_eq(itb_encryptor_encrypt(a, plaintext, pt_len, &ct_a, &ct_a_len), ITB_OK);
    uint8_t *pt_a = NULL; size_t pt_a_len = 0;
    ck_assert_int_eq(itb_encryptor_decrypt(a, ct_a, ct_a_len, &pt_a, &pt_a_len), ITB_OK);
    ck_assert_mem_eq(pt_a, plaintext, pt_len);

    uint8_t *ct_b = NULL; size_t ct_b_len = 0;
    ck_assert_int_eq(itb_encryptor_encrypt(b, plaintext, pt_len, &ct_b, &ct_b_len), ITB_OK);
    uint8_t *pt_b = NULL; size_t pt_b_len = 0;
    ck_assert_int_eq(itb_encryptor_decrypt(b, ct_b, ct_b_len, &pt_b, &pt_b_len), ITB_OK);
    ck_assert_mem_eq(pt_b, plaintext, pt_len);

    itb_buffer_free(ct_a);
    itb_buffer_free(pt_a);
    itb_buffer_free(ct_b);
    itb_buffer_free(pt_b);
    itb_encryptor_free(a);
    itb_encryptor_free(b);
}
END_TEST

int main(void)
{
    Suite *s = suite_create("easy_nonce_sizes");
    TCase *tc = tcase_create("core");
    tcase_set_timeout(tc, 120);
    tcase_add_test(tc, test_easy_nonce_sizes_header_size_default_is_20);
    tcase_add_test(tc, test_easy_nonce_sizes_header_size_dynamic);
    tcase_add_test(tc, test_easy_nonce_sizes_encrypt_decrypt_across_single);
    tcase_add_test(tc, test_easy_nonce_sizes_encrypt_decrypt_across_triple);
    tcase_add_test(tc, test_easy_nonce_sizes_auth_across_single);
    tcase_add_test(tc, test_easy_nonce_sizes_auth_across_triple);
    tcase_add_test(tc, test_easy_nonce_sizes_two_encryptors_independent_nonce_bits);
    suite_add_tcase(s, tc);

    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int failures = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failures == 0 ? 0 : 1;
}
