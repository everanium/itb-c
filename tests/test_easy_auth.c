/*
 * test_easy_auth.c — authenticated encryption coverage on the
 * high-level Encryptor surface.
 *
 * Mirrors bindings/rust/tests/test_easy_auth.rs one-to-one. Same matrix
 * (3 MACs × 3 hash widths × {Single, Triple} round-trip plus tamper
 * rejection); cross-MAC structural rejection rides through the
 * itb_encryptor_export / itb_encryptor_import path with
 * itb_easy_last_mismatch_field reporting "mac"; same-primitive
 * different-key MAC failure verifies that two independently-constructed
 * encryptors collide on ITB_MAC_FAILURE rather than yielding corrupted
 * plaintext.
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

static const char *CANONICAL_MACS[] = {"kmac256", "hmac-sha256", "hmac-blake3"};
#define CANONICAL_MACS_COUNT (sizeof(CANONICAL_MACS) / sizeof(CANONICAL_MACS[0]))

static const char *HASH_BY_WIDTH[] = {"siphash24", "blake3", "blake2b512"};
#define HASH_BY_WIDTH_COUNT (sizeof(HASH_BY_WIDTH) / sizeof(HASH_BY_WIDTH[0]))

static uint8_t *token_bytes(size_t n) {
    static uint64_t ctr = 0xCAFEBABEDEADBEEFULL;
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

START_TEST(test_easy_auth_all_macs_all_widths_single)
{
    size_t pt_len = 4096;
    uint8_t *plaintext = token_bytes(pt_len);

    for (size_t m = 0; m < CANONICAL_MACS_COUNT; m++) {
        for (size_t h = 0; h < HASH_BY_WIDTH_COUNT; h++) {
            itb_encryptor_t *enc = NULL;
            ck_assert_int_eq(itb_encryptor_new(HASH_BY_WIDTH[h], 1024,
                                               CANONICAL_MACS[m], 1, &enc), ITB_OK);

            uint8_t *ct = NULL; size_t ct_len = 0;
            ck_assert_int_eq(itb_encryptor_encrypt_auth(enc, plaintext, pt_len,
                                                        &ct, &ct_len), ITB_OK);
            uint8_t *pt = NULL; size_t pt_out_len = 0;
            ck_assert_int_eq(itb_encryptor_decrypt_auth(enc, ct, ct_len,
                                                        &pt, &pt_out_len), ITB_OK);
            ck_assert_uint_eq(pt_out_len, pt_len);
            ck_assert_mem_eq(pt, plaintext, pt_len);

            /* Tamper: flip 256 bytes past the dynamic header. */
            int hsize = 0;
            ck_assert_int_eq(itb_encryptor_header_size(enc, &hsize), ITB_OK);
            size_t end = (size_t)hsize + 256;
            if (end > ct_len) end = ct_len;
            for (size_t b = (size_t)hsize; b < end; b++) {
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

START_TEST(test_easy_auth_all_macs_all_widths_triple)
{
    size_t pt_len = 4096;
    uint8_t *plaintext = token_bytes(pt_len);

    for (size_t m = 0; m < CANONICAL_MACS_COUNT; m++) {
        for (size_t h = 0; h < HASH_BY_WIDTH_COUNT; h++) {
            itb_encryptor_t *enc = NULL;
            ck_assert_int_eq(itb_encryptor_new(HASH_BY_WIDTH[h], 1024,
                                               CANONICAL_MACS[m], 3, &enc), ITB_OK);

            uint8_t *ct = NULL; size_t ct_len = 0;
            ck_assert_int_eq(itb_encryptor_encrypt_auth(enc, plaintext, pt_len,
                                                        &ct, &ct_len), ITB_OK);
            uint8_t *pt = NULL; size_t pt_out_len = 0;
            ck_assert_int_eq(itb_encryptor_decrypt_auth(enc, ct, ct_len,
                                                        &pt, &pt_out_len), ITB_OK);
            ck_assert_uint_eq(pt_out_len, pt_len);
            ck_assert_mem_eq(pt, plaintext, pt_len);

            int hsize = 0;
            ck_assert_int_eq(itb_encryptor_header_size(enc, &hsize), ITB_OK);
            size_t end = (size_t)hsize + 256;
            if (end > ct_len) end = ct_len;
            for (size_t b = (size_t)hsize; b < end; b++) {
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

START_TEST(test_easy_auth_cross_mac_rejection_different_primitive)
{
    /* Sender uses kmac256; receiver uses hmac-sha256 — Import must
     * reject on field=mac. */
    itb_encryptor_t *src = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &src), ITB_OK);
    uint8_t *blob = NULL; size_t blob_len = 0;
    ck_assert_int_eq(itb_encryptor_export(src, &blob, &blob_len), ITB_OK);
    itb_encryptor_free(src);

    itb_encryptor_t *dst = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "hmac-sha256", 1, &dst), ITB_OK);
    ck_assert_int_eq(itb_encryptor_import(dst, blob, blob_len), ITB_EASY_MISMATCH);

    char fbuf[64]; size_t flen = 0;
    ck_assert_int_eq(itb_easy_last_mismatch_field(fbuf, sizeof(fbuf), &flen), ITB_OK);
    ck_assert_str_eq(fbuf, "mac");

    itb_buffer_free(blob);
    itb_encryptor_free(dst);
}
END_TEST

START_TEST(test_easy_auth_same_primitive_different_key_mac_failure)
{
    static const uint8_t plaintext[] = "authenticated payload";
    size_t pt_len = sizeof(plaintext) - 1;

    itb_encryptor_t *enc1 = NULL;
    itb_encryptor_t *enc2 = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "hmac-sha256", 1, &enc1), ITB_OK);
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "hmac-sha256", 1, &enc2), ITB_OK);

    /* Day 1: encrypt with enc1's seeds and MAC key. */
    uint8_t *ct = NULL; size_t ct_len = 0;
    ck_assert_int_eq(itb_encryptor_encrypt_auth(enc1, plaintext, pt_len,
                                                &ct, &ct_len), ITB_OK);
    /* Day 2: enc2 has its own (different) seed / MAC keys — decrypt
     * must fail with ITB_MAC_FAILURE rather than corrupted plaintext. */
    uint8_t *bad = NULL; size_t bad_len = 0;
    ck_assert_int_eq(itb_encryptor_decrypt_auth(enc2, ct, ct_len, &bad, &bad_len),
                     ITB_MAC_FAILURE);
    ck_assert_ptr_null(bad);

    itb_buffer_free(ct);
    itb_encryptor_free(enc1);
    itb_encryptor_free(enc2);
}
END_TEST

int main(void)
{
    Suite *s = suite_create("easy_auth");
    TCase *tc = tcase_create("core");
    tcase_set_timeout(tc, 120);
    tcase_add_test(tc, test_easy_auth_all_macs_all_widths_single);
    tcase_add_test(tc, test_easy_auth_all_macs_all_widths_triple);
    tcase_add_test(tc, test_easy_auth_cross_mac_rejection_different_primitive);
    tcase_add_test(tc, test_easy_auth_same_primitive_different_key_mac_failure);
    suite_add_tcase(s, tc);

    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int failures = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failures == 0 ? 0 : 1;
}
