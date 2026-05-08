/*
 * test_nonce_sizes.c — round-trip tests across all nonce-size
 * configurations.
 *
 * Mirrors bindings/rust/tests/test_nonce_sizes.rs one-to-one. ITB
 * exposes a runtime-configurable nonce size (itb_set_nonce_bits) that
 * takes one of {128, 256, 512}. The on-the-wire chunk header therefore
 * varies between 20, 36, and 68 bytes; every consumer that walks
 * ciphertext on the byte level (chunk parsers, tampering tests,
 * streaming decoders) must use itb_header_size rather than a hardcoded
 * constant.
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

static const char *MAC_NAMES[] = {"kmac256", "hmac-sha256", "hmac-blake3"};
#define MAC_NAMES_COUNT (sizeof(MAC_NAMES) / sizeof(MAC_NAMES[0]))

static const uint8_t MAC_KEY[32] = {
    0x73,0x73,0x73,0x73,0x73,0x73,0x73,0x73,
    0x73,0x73,0x73,0x73,0x73,0x73,0x73,0x73,
    0x73,0x73,0x73,0x73,0x73,0x73,0x73,0x73,
    0x73,0x73,0x73,0x73,0x73,0x73,0x73,0x73,
};

static uint8_t *pseudo_plaintext(size_t n) {
    uint8_t *p = (uint8_t *) malloc(n == 0 ? 1 : n);
    ck_assert_ptr_nonnull(p);
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t) (((i * 31u) + 7u) & 0xffu);
    }
    return p;
}

START_TEST(test_nonce_sizes_default_is_20)
{
    int prev = itb_get_nonce_bits();
    ck_assert_int_eq(itb_set_nonce_bits(128), ITB_OK);
    ck_assert_int_eq(itb_header_size(), 20);
    ck_assert_int_eq(itb_get_nonce_bits(), 128);
    ck_assert_int_eq(itb_set_nonce_bits(prev), ITB_OK);
}
END_TEST

START_TEST(test_nonce_sizes_header_size_dynamic)
{
    int prev = itb_get_nonce_bits();
    for (size_t i = 0; i < NONCE_SIZES_COUNT; i++) {
        ck_assert_int_eq(itb_set_nonce_bits(NONCE_SIZES[i]), ITB_OK);
        ck_assert_int_eq(itb_header_size(), NONCE_SIZES[i] / 8 + 4);
    }
    ck_assert_int_eq(itb_set_nonce_bits(prev), ITB_OK);
}
END_TEST

START_TEST(test_nonce_sizes_encrypt_decrypt_across_nonce_sizes)
{
    int prev = itb_get_nonce_bits();
    size_t pt_len = 1024;
    uint8_t *plaintext = pseudo_plaintext(pt_len);

    for (size_t ni = 0; ni < NONCE_SIZES_COUNT; ni++) {
        for (size_t hi = 0; hi < HASHES_COUNT; hi++) {
            ck_assert_int_eq(itb_set_nonce_bits(NONCE_SIZES[ni]), ITB_OK);
            const char *hash_name = HASHES[hi];

            itb_seed_t *ns = NULL, *ds = NULL, *ss = NULL;
            ck_assert_int_eq(itb_seed_new(hash_name, 1024, &ns), ITB_OK);
            ck_assert_int_eq(itb_seed_new(hash_name, 1024, &ds), ITB_OK);
            ck_assert_int_eq(itb_seed_new(hash_name, 1024, &ss), ITB_OK);

            uint8_t *ct = NULL; size_t ct_len = 0;
            ck_assert_int_eq(itb_encrypt(ns, ds, ss, plaintext, pt_len, &ct, &ct_len), ITB_OK);
            uint8_t *pt = NULL; size_t pt_out_len = 0;
            ck_assert_int_eq(itb_decrypt(ns, ds, ss, ct, ct_len, &pt, &pt_out_len), ITB_OK);
            ck_assert_uint_eq(pt_out_len, pt_len);
            ck_assert_mem_eq(pt, plaintext, pt_len);

            /* parse_chunk_len must report the full chunk length. */
            size_t hsize = (size_t) itb_header_size();
            size_t chunk_len = 0;
            ck_assert_int_eq(itb_parse_chunk_len(ct, hsize, &chunk_len), ITB_OK);
            ck_assert_uint_eq(chunk_len, ct_len);

            itb_buffer_free(ct);
            itb_buffer_free(pt);
            itb_seed_free(ns);
            itb_seed_free(ds);
            itb_seed_free(ss);
        }
    }
    free(plaintext);
    ck_assert_int_eq(itb_set_nonce_bits(prev), ITB_OK);
}
END_TEST

START_TEST(test_nonce_sizes_triple_encrypt_decrypt_across_nonce_sizes)
{
    int prev = itb_get_nonce_bits();
    size_t pt_len = 1024;
    uint8_t *plaintext = pseudo_plaintext(pt_len);

    for (size_t ni = 0; ni < NONCE_SIZES_COUNT; ni++) {
        for (size_t hi = 0; hi < HASHES_COUNT; hi++) {
            ck_assert_int_eq(itb_set_nonce_bits(NONCE_SIZES[ni]), ITB_OK);
            const char *hash_name = HASHES[hi];

            itb_seed_t *seeds[7] = {NULL};
            for (int k = 0; k < 7; k++) {
                ck_assert_int_eq(itb_seed_new(hash_name, 1024, &seeds[k]), ITB_OK);
            }

            uint8_t *ct = NULL; size_t ct_len = 0;
            ck_assert_int_eq(itb_encrypt_triple(seeds[0], seeds[1], seeds[2], seeds[3],
                                                seeds[4], seeds[5], seeds[6],
                                                plaintext, pt_len, &ct, &ct_len), ITB_OK);
            uint8_t *pt = NULL; size_t pt_out_len = 0;
            ck_assert_int_eq(itb_decrypt_triple(seeds[0], seeds[1], seeds[2], seeds[3],
                                                seeds[4], seeds[5], seeds[6],
                                                ct, ct_len, &pt, &pt_out_len), ITB_OK);
            ck_assert_uint_eq(pt_out_len, pt_len);
            ck_assert_mem_eq(pt, plaintext, pt_len);

            itb_buffer_free(ct);
            itb_buffer_free(pt);
            for (int k = 0; k < 7; k++) itb_seed_free(seeds[k]);
        }
    }
    free(plaintext);
    ck_assert_int_eq(itb_set_nonce_bits(prev), ITB_OK);
}
END_TEST

START_TEST(test_nonce_sizes_auth_across_nonce_sizes)
{
    int prev = itb_get_nonce_bits();
    size_t pt_len = 1024;
    uint8_t *plaintext = pseudo_plaintext(pt_len);

    for (size_t ni = 0; ni < NONCE_SIZES_COUNT; ni++) {
        for (size_t mi = 0; mi < MAC_NAMES_COUNT; mi++) {
            ck_assert_int_eq(itb_set_nonce_bits(NONCE_SIZES[ni]), ITB_OK);

            itb_mac_t *mac = NULL;
            ck_assert_int_eq(itb_mac_new(MAC_NAMES[mi], MAC_KEY, sizeof(MAC_KEY), &mac), ITB_OK);
            itb_seed_t *ns = NULL, *ds = NULL, *ss = NULL;
            ck_assert_int_eq(itb_seed_new("blake3", 1024, &ns), ITB_OK);
            ck_assert_int_eq(itb_seed_new("blake3", 1024, &ds), ITB_OK);
            ck_assert_int_eq(itb_seed_new("blake3", 1024, &ss), ITB_OK);

            uint8_t *ct = NULL; size_t ct_len = 0;
            ck_assert_int_eq(itb_encrypt_auth(ns, ds, ss, mac,
                                              plaintext, pt_len, &ct, &ct_len), ITB_OK);
            uint8_t *pt = NULL; size_t pt_out_len = 0;
            ck_assert_int_eq(itb_decrypt_auth(ns, ds, ss, mac,
                                              ct, ct_len, &pt, &pt_out_len), ITB_OK);
            ck_assert_uint_eq(pt_out_len, pt_len);
            ck_assert_mem_eq(pt, plaintext, pt_len);

            size_t hsize = (size_t) itb_header_size();
            size_t end = hsize + 256;
            if (end > ct_len) end = ct_len;
            for (size_t b = hsize; b < end; b++) {
                ct[b] ^= 0x01;
            }
            uint8_t *bad = NULL; size_t bad_len = 0;
            ck_assert_int_eq(itb_decrypt_auth(ns, ds, ss, mac,
                                              ct, ct_len, &bad, &bad_len),
                             ITB_MAC_FAILURE);
            ck_assert_ptr_null(bad);

            itb_buffer_free(ct);
            itb_buffer_free(pt);
            itb_seed_free(ns);
            itb_seed_free(ds);
            itb_seed_free(ss);
            itb_mac_free(mac);
        }
    }
    free(plaintext);
    ck_assert_int_eq(itb_set_nonce_bits(prev), ITB_OK);
}
END_TEST

START_TEST(test_nonce_sizes_triple_auth_across_nonce_sizes)
{
    int prev = itb_get_nonce_bits();
    size_t pt_len = 1024;
    uint8_t *plaintext = pseudo_plaintext(pt_len);

    for (size_t ni = 0; ni < NONCE_SIZES_COUNT; ni++) {
        for (size_t mi = 0; mi < MAC_NAMES_COUNT; mi++) {
            ck_assert_int_eq(itb_set_nonce_bits(NONCE_SIZES[ni]), ITB_OK);

            itb_mac_t *mac = NULL;
            ck_assert_int_eq(itb_mac_new(MAC_NAMES[mi], MAC_KEY, sizeof(MAC_KEY), &mac), ITB_OK);
            itb_seed_t *seeds[7] = {NULL};
            for (int k = 0; k < 7; k++) {
                ck_assert_int_eq(itb_seed_new("blake3", 1024, &seeds[k]), ITB_OK);
            }

            uint8_t *ct = NULL; size_t ct_len = 0;
            ck_assert_int_eq(itb_encrypt_auth_triple(seeds[0], seeds[1], seeds[2], seeds[3],
                                                     seeds[4], seeds[5], seeds[6], mac,
                                                     plaintext, pt_len, &ct, &ct_len), ITB_OK);
            uint8_t *pt = NULL; size_t pt_out_len = 0;
            ck_assert_int_eq(itb_decrypt_auth_triple(seeds[0], seeds[1], seeds[2], seeds[3],
                                                     seeds[4], seeds[5], seeds[6], mac,
                                                     ct, ct_len, &pt, &pt_out_len), ITB_OK);
            ck_assert_uint_eq(pt_out_len, pt_len);
            ck_assert_mem_eq(pt, plaintext, pt_len);

            size_t hsize = (size_t) itb_header_size();
            size_t end = hsize + 256;
            if (end > ct_len) end = ct_len;
            for (size_t b = hsize; b < end; b++) {
                ct[b] ^= 0x01;
            }
            uint8_t *bad = NULL; size_t bad_len = 0;
            ck_assert_int_eq(itb_decrypt_auth_triple(seeds[0], seeds[1], seeds[2], seeds[3],
                                                     seeds[4], seeds[5], seeds[6], mac,
                                                     ct, ct_len, &bad, &bad_len),
                             ITB_MAC_FAILURE);
            ck_assert_ptr_null(bad);

            itb_buffer_free(ct);
            itb_buffer_free(pt);
            for (int k = 0; k < 7; k++) itb_seed_free(seeds[k]);
            itb_mac_free(mac);
        }
    }
    free(plaintext);
    ck_assert_int_eq(itb_set_nonce_bits(prev), ITB_OK);
}
END_TEST

int main(void)
{
    Suite *s = suite_create("nonce_sizes");
    TCase *tc = tcase_create("core");
    tcase_set_timeout(tc, 120);
    tcase_add_test(tc, test_nonce_sizes_default_is_20);
    tcase_add_test(tc, test_nonce_sizes_header_size_dynamic);
    tcase_add_test(tc, test_nonce_sizes_encrypt_decrypt_across_nonce_sizes);
    tcase_add_test(tc, test_nonce_sizes_triple_encrypt_decrypt_across_nonce_sizes);
    tcase_add_test(tc, test_nonce_sizes_auth_across_nonce_sizes);
    tcase_add_test(tc, test_nonce_sizes_triple_auth_across_nonce_sizes);
    suite_add_tcase(s, tc);

    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int failures = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failures == 0 ? 0 : 1;
}
