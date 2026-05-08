/*
 * test_easy_siphash24.c — SipHash-2-4-focused Encryptor (Easy Mode) coverage.
 *
 * Mirrors bindings/rust/tests/test_easy_siphash24.rs one-to-one.
 * SipHash ships only at -128 and is the unique primitive with no
 * fixed PRF key — itb_encryptor_has_prf_keys reports 0; the persistence
 * path therefore exports / imports without prf_keys carried in the
 * JSON blob, and the seed components alone reconstruct the SipHash
 * keying material.
 *
 * Per-binary fork() isolation gives this test its own libitb global
 * state, so no in-process serial lock is required.
 *
 * `itb_encryptor_set_nonce_bits` is per-instance and does not touch
 * process-global state.
 */

#include <check.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "itb.h"

static const struct { const char *name; int width; } SIPHASH_HASHES[] = {
    {"siphash24", 128},
};
#define SIPHASH_HASHES_COUNT (sizeof(SIPHASH_HASHES) / sizeof(SIPHASH_HASHES[0]))

static const int NONCE_SIZES[] = {128, 256, 512};
#define NONCE_SIZES_COUNT (sizeof(NONCE_SIZES) / sizeof(NONCE_SIZES[0]))

static const char *MAC_NAMES[] = {"kmac256", "hmac-sha256", "hmac-blake3"};
#define MAC_NAMES_COUNT (sizeof(MAC_NAMES) / sizeof(MAC_NAMES[0]))

static uint8_t *token_bytes(size_t n) {
    static uint64_t ctr = 0xDEADBEEFCAFEBABEULL;
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

START_TEST(test_easy_siphash24_roundtrip_across_nonce_sizes)
{
    size_t pt_len = 1024;
    uint8_t *plaintext = token_bytes(pt_len);

    for (size_t i = 0; i < NONCE_SIZES_COUNT; i++) {
        for (size_t j = 0; j < SIPHASH_HASHES_COUNT; j++) {
            const char *hash_name = SIPHASH_HASHES[j].name;
            itb_encryptor_t *enc = NULL;
            ck_assert_int_eq(itb_encryptor_new(hash_name, 1024, "kmac256", 1, &enc), ITB_OK);
            ck_assert_int_eq(itb_encryptor_set_nonce_bits(enc, NONCE_SIZES[i]), ITB_OK);

            uint8_t *ct = NULL; size_t ct_len = 0;
            ck_assert_int_eq(itb_encryptor_encrypt(enc, plaintext, pt_len, &ct, &ct_len), ITB_OK);
            uint8_t *pt = NULL; size_t pt_out_len = 0;
            ck_assert_int_eq(itb_encryptor_decrypt(enc, ct, ct_len, &pt, &pt_out_len), ITB_OK);
            ck_assert_uint_eq(pt_out_len, pt_len);
            ck_assert_mem_eq(pt, plaintext, pt_len);

            itb_buffer_free(ct);
            itb_buffer_free(pt);
            itb_encryptor_free(enc);
        }
    }
    free(plaintext);
}
END_TEST

START_TEST(test_easy_siphash24_triple_roundtrip_across_nonce_sizes)
{
    size_t pt_len = 1024;
    uint8_t *plaintext = token_bytes(pt_len);

    for (size_t i = 0; i < NONCE_SIZES_COUNT; i++) {
        for (size_t j = 0; j < SIPHASH_HASHES_COUNT; j++) {
            const char *hash_name = SIPHASH_HASHES[j].name;
            itb_encryptor_t *enc = NULL;
            ck_assert_int_eq(itb_encryptor_new(hash_name, 1024, "kmac256", 3, &enc), ITB_OK);
            ck_assert_int_eq(itb_encryptor_set_nonce_bits(enc, NONCE_SIZES[i]), ITB_OK);

            uint8_t *ct = NULL; size_t ct_len = 0;
            ck_assert_int_eq(itb_encryptor_encrypt(enc, plaintext, pt_len, &ct, &ct_len), ITB_OK);
            uint8_t *pt = NULL; size_t pt_out_len = 0;
            ck_assert_int_eq(itb_encryptor_decrypt(enc, ct, ct_len, &pt, &pt_out_len), ITB_OK);
            ck_assert_uint_eq(pt_out_len, pt_len);
            ck_assert_mem_eq(pt, plaintext, pt_len);

            itb_buffer_free(ct);
            itb_buffer_free(pt);
            itb_encryptor_free(enc);
        }
    }
    free(plaintext);
}
END_TEST

START_TEST(test_easy_siphash24_auth_across_nonce_sizes)
{
    size_t pt_len = 1024;
    uint8_t *plaintext = token_bytes(pt_len);

    for (size_t i = 0; i < NONCE_SIZES_COUNT; i++) {
        for (size_t m = 0; m < MAC_NAMES_COUNT; m++) {
            for (size_t j = 0; j < SIPHASH_HASHES_COUNT; j++) {
                const char *hash_name = SIPHASH_HASHES[j].name;
                itb_encryptor_t *enc = NULL;
                ck_assert_int_eq(itb_encryptor_new(hash_name, 1024, MAC_NAMES[m], 1, &enc), ITB_OK);
                ck_assert_int_eq(itb_encryptor_set_nonce_bits(enc, NONCE_SIZES[i]), ITB_OK);

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
                ck_assert_int_gt(hsize, 0);
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
    }
    free(plaintext);
}
END_TEST

START_TEST(test_easy_siphash24_triple_auth_across_nonce_sizes)
{
    size_t pt_len = 1024;
    uint8_t *plaintext = token_bytes(pt_len);

    for (size_t i = 0; i < NONCE_SIZES_COUNT; i++) {
        for (size_t m = 0; m < MAC_NAMES_COUNT; m++) {
            for (size_t j = 0; j < SIPHASH_HASHES_COUNT; j++) {
                const char *hash_name = SIPHASH_HASHES[j].name;
                itb_encryptor_t *enc = NULL;
                ck_assert_int_eq(itb_encryptor_new(hash_name, 1024, MAC_NAMES[m], 3, &enc), ITB_OK);
                ck_assert_int_eq(itb_encryptor_set_nonce_bits(enc, NONCE_SIZES[i]), ITB_OK);

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
                ck_assert_int_gt(hsize, 0);
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
    }
    free(plaintext);
}
END_TEST

START_TEST(test_easy_siphash24_persistence_across_nonce_sizes)
{
    /* Persistence sweep without prf_keys: SipHash's seed components
     * alone reconstruct the keying material. The exported blob omits
     * prf_keys, and import on a fresh encryptor restores the seeds
     * without consulting them. */
    static const char prefix[] = "persistence payload ";
    size_t prefix_len = sizeof(prefix) - 1;
    size_t tail_len = 1024;
    uint8_t *tail = token_bytes(tail_len);
    size_t pt_len = prefix_len + tail_len;
    uint8_t *plaintext = (uint8_t *)malloc(pt_len);
    ck_assert_ptr_nonnull(plaintext);
    memcpy(plaintext, prefix, prefix_len);
    memcpy(plaintext + prefix_len, tail, tail_len);
    free(tail);

    for (size_t hi = 0; hi < SIPHASH_HASHES_COUNT; hi++) {
        const char *hash_name = SIPHASH_HASHES[hi].name;
        int width = SIPHASH_HASHES[hi].width;
        const int candidate_kb[] = {512, 1024, 2048};
        for (size_t ki = 0; ki < sizeof(candidate_kb) / sizeof(candidate_kb[0]); ki++) {
            int kb = candidate_kb[ki];
            if (kb % width != 0) continue;
            for (size_t i = 0; i < NONCE_SIZES_COUNT; i++) {
                itb_encryptor_t *src = NULL;
                ck_assert_int_eq(itb_encryptor_new(hash_name, kb, "kmac256", 1, &src), ITB_OK);
                ck_assert_int_eq(itb_encryptor_set_nonce_bits(src, NONCE_SIZES[i]), ITB_OK);

                int has_prf = 1;
                ck_assert_int_eq(itb_encryptor_has_prf_keys(src, &has_prf), ITB_OK);
                ck_assert_int_eq(has_prf, 0);

                uint64_t comps[32];
                size_t cn = 0;
                ck_assert_int_eq(itb_encryptor_seed_components(src, 0, comps, 32, &cn), ITB_OK);
                ck_assert_uint_eq(cn * 64u, (size_t)kb);

                uint8_t *blob = NULL; size_t blob_len = 0;
                ck_assert_int_eq(itb_encryptor_export(src, &blob, &blob_len), ITB_OK);
                ck_assert_uint_gt(blob_len, 0);

                uint8_t *ct = NULL; size_t ct_len = 0;
                ck_assert_int_eq(itb_encryptor_encrypt(src, plaintext, pt_len,
                                                       &ct, &ct_len), ITB_OK);
                ck_assert_int_eq(itb_encryptor_close(src), ITB_OK);
                itb_encryptor_free(src);

                itb_encryptor_t *dst = NULL;
                ck_assert_int_eq(itb_encryptor_new(hash_name, kb, "kmac256", 1, &dst), ITB_OK);
                ck_assert_int_eq(itb_encryptor_set_nonce_bits(dst, NONCE_SIZES[i]), ITB_OK);
                ck_assert_int_eq(itb_encryptor_import(dst, blob, blob_len), ITB_OK);

                uint8_t *pt = NULL; size_t pt_out_len = 0;
                ck_assert_int_eq(itb_encryptor_decrypt(dst, ct, ct_len, &pt, &pt_out_len), ITB_OK);
                ck_assert_uint_eq(pt_out_len, pt_len);
                ck_assert_mem_eq(pt, plaintext, pt_len);

                itb_buffer_free(blob);
                itb_buffer_free(ct);
                itb_buffer_free(pt);
                itb_encryptor_free(dst);
            }
        }
    }
    free(plaintext);
}
END_TEST

START_TEST(test_easy_siphash24_roundtrip_sizes)
{
    static const size_t SIZES[] = {1, 17, 4096, 65536, 1u << 20};
    for (size_t hi = 0; hi < SIPHASH_HASHES_COUNT; hi++) {
        const char *hash_name = SIPHASH_HASHES[hi].name;
        for (size_t i = 0; i < NONCE_SIZES_COUNT; i++) {
            for (size_t si = 0; si < sizeof(SIZES) / sizeof(SIZES[0]); si++) {
                size_t sz = SIZES[si];
                uint8_t *plaintext = token_bytes(sz);

                itb_encryptor_t *enc = NULL;
                ck_assert_int_eq(itb_encryptor_new(hash_name, 1024, "kmac256", 1, &enc), ITB_OK);
                ck_assert_int_eq(itb_encryptor_set_nonce_bits(enc, NONCE_SIZES[i]), ITB_OK);

                uint8_t *ct = NULL; size_t ct_len = 0;
                ck_assert_int_eq(itb_encryptor_encrypt(enc, plaintext, sz, &ct, &ct_len), ITB_OK);
                uint8_t *pt = NULL; size_t pt_out_len = 0;
                ck_assert_int_eq(itb_encryptor_decrypt(enc, ct, ct_len, &pt, &pt_out_len), ITB_OK);
                ck_assert_uint_eq(pt_out_len, sz);
                ck_assert_mem_eq(pt, plaintext, sz);

                free(plaintext);
                itb_buffer_free(ct);
                itb_buffer_free(pt);
                itb_encryptor_free(enc);
            }
        }
    }
}
END_TEST

int main(void)
{
    Suite *s = suite_create("easy_siphash24");
    TCase *tc = tcase_create("core");
    tcase_set_timeout(tc, 60);
    tcase_add_test(tc, test_easy_siphash24_roundtrip_across_nonce_sizes);
    tcase_add_test(tc, test_easy_siphash24_triple_roundtrip_across_nonce_sizes);
    tcase_add_test(tc, test_easy_siphash24_auth_across_nonce_sizes);
    tcase_add_test(tc, test_easy_siphash24_triple_auth_across_nonce_sizes);
    tcase_add_test(tc, test_easy_siphash24_persistence_across_nonce_sizes);
    tcase_add_test(tc, test_easy_siphash24_roundtrip_sizes);
    suite_add_tcase(s, tc);

    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int failures = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failures == 0 ? 0 : 1;
}
