/*
 * test_easy_blake3.c — BLAKE3-focused Encryptor (Easy Mode) coverage.
 *
 * Mirrors bindings/rust/tests/test_easy_blake3.rs one-to-one. BLAKE3
 * ships at a single width (-256). Each Rust `#[test] fn` becomes a
 * single START_TEST / END_TEST block here; the cargo serial-lock
 * guard is implicit because each test_*.c file is built as its own
 * binary, giving per-process isolation.
 *
 * `itb_encryptor_set_nonce_bits` is per-instance and does not touch
 * process-global state, so these tests do not need serial sequencing.
 *
 * Two extra blocks land in this file (Phase 5C scope, not in the Rust
 * source-of-truth) to cover the binding-side default-MAC override and
 * pre-FFI mode rejection contracts surfaced by itb_encryptor_new:
 *   - test_easy_blake3_default_mac_override
 *   - test_easy_blake3_mode_rejection
 * Both are covered once across the Phase 5C suite per the task
 * specification; this file is the chosen carrier.
 */

#include <check.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "itb.h"

static const struct { const char *name; int width; } BLAKE3_HASHES[] = {
    {"blake3", 256},
};
#define BLAKE3_HASHES_COUNT (sizeof(BLAKE3_HASHES) / sizeof(BLAKE3_HASHES[0]))

static size_t expected_key_len(const char *name) {
    if (strcmp(name, "blake3") == 0) return 32;
    ck_abort_msg("unknown hash %s", name);
    return 0;
}

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

START_TEST(test_easy_blake3_roundtrip_across_nonce_sizes)
{
    size_t pt_len = 1024;
    uint8_t *plaintext = token_bytes(pt_len);

    for (size_t i = 0; i < NONCE_SIZES_COUNT; i++) {
        for (size_t j = 0; j < BLAKE3_HASHES_COUNT; j++) {
            const char *hash_name = BLAKE3_HASHES[j].name;
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

START_TEST(test_easy_blake3_triple_roundtrip_across_nonce_sizes)
{
    size_t pt_len = 1024;
    uint8_t *plaintext = token_bytes(pt_len);

    for (size_t i = 0; i < NONCE_SIZES_COUNT; i++) {
        for (size_t j = 0; j < BLAKE3_HASHES_COUNT; j++) {
            const char *hash_name = BLAKE3_HASHES[j].name;
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

START_TEST(test_easy_blake3_auth_across_nonce_sizes)
{
    size_t pt_len = 1024;
    uint8_t *plaintext = token_bytes(pt_len);

    for (size_t i = 0; i < NONCE_SIZES_COUNT; i++) {
        for (size_t m = 0; m < MAC_NAMES_COUNT; m++) {
            for (size_t j = 0; j < BLAKE3_HASHES_COUNT; j++) {
                const char *hash_name = BLAKE3_HASHES[j].name;
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

START_TEST(test_easy_blake3_triple_auth_across_nonce_sizes)
{
    size_t pt_len = 1024;
    uint8_t *plaintext = token_bytes(pt_len);

    for (size_t i = 0; i < NONCE_SIZES_COUNT; i++) {
        for (size_t m = 0; m < MAC_NAMES_COUNT; m++) {
            for (size_t j = 0; j < BLAKE3_HASHES_COUNT; j++) {
                const char *hash_name = BLAKE3_HASHES[j].name;
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

START_TEST(test_easy_blake3_persistence_across_nonce_sizes)
{
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

    for (size_t hi = 0; hi < BLAKE3_HASHES_COUNT; hi++) {
        const char *hash_name = BLAKE3_HASHES[hi].name;
        int width = BLAKE3_HASHES[hi].width;
        const int candidate_kb[] = {512, 1024, 2048};
        for (size_t ki = 0; ki < sizeof(candidate_kb) / sizeof(candidate_kb[0]); ki++) {
            int kb = candidate_kb[ki];
            if (kb % width != 0) continue;
            for (size_t i = 0; i < NONCE_SIZES_COUNT; i++) {
                itb_encryptor_t *src = NULL;
                ck_assert_int_eq(itb_encryptor_new(hash_name, kb, "kmac256", 1, &src), ITB_OK);
                ck_assert_int_eq(itb_encryptor_set_nonce_bits(src, NONCE_SIZES[i]), ITB_OK);

                /* PRF key length read via fixed-size buffer (every shipped
                 * Easy Mode primitive has a fixed key bounded by 64 bytes;
                 * SipHash is the lone no-PRF-key exception, exercised in
                 * test_easy_siphash24.c). */
                uint8_t prf_key[64];
                size_t kl = 0;
                ck_assert_int_eq(itb_encryptor_prf_key(src, 0, prf_key, sizeof(prf_key), &kl),
                                 ITB_OK);
                ck_assert_uint_eq(kl, expected_key_len(hash_name));

                /* Components count read via fixed-size buffer (max 32 lanes
                 * = 2048 bits / 64 bits per lane). */
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

START_TEST(test_easy_blake3_roundtrip_sizes)
{
    static const size_t SIZES[] = {1, 17, 4096, 65536, 1u << 20};
    for (size_t hi = 0; hi < BLAKE3_HASHES_COUNT; hi++) {
        const char *hash_name = BLAKE3_HASHES[hi].name;
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

START_TEST(test_easy_blake3_default_mac_override)
{
    /* §6 contract: when `mac_name` is NULL or "", the binding rewrites
     * to "hmac-blake3" before forwarding to libitb. Confirm via
     * itb_encryptor_mac_name on both null-pointer and empty-string
     * inputs. */
    const char *mac_inputs[] = {NULL, ""};
    for (size_t k = 0; k < sizeof(mac_inputs) / sizeof(mac_inputs[0]); k++) {
        itb_encryptor_t *enc = NULL;
        ck_assert_int_eq(itb_encryptor_new("blake3", 1024, mac_inputs[k], 1, &enc), ITB_OK);

        char buf[64];
        size_t mlen = 0;
        ck_assert_int_eq(itb_encryptor_mac_name(enc, buf, sizeof(buf), &mlen), ITB_OK);
        ck_assert_str_eq(buf, "hmac-blake3");

        itb_encryptor_free(enc);
    }
}
END_TEST

START_TEST(test_easy_blake3_mode_rejection)
{
    /* §11.k contract: only mode 1 (Single) and mode 3 (Triple) are
     * accepted; the binding rejects every other value with
     * ITB_BAD_INPUT before the FFI call. */
    static const int BAD_MODES[] = {0, 2, 4, -1, 7};
    for (size_t k = 0; k < sizeof(BAD_MODES) / sizeof(BAD_MODES[0]); k++) {
        itb_encryptor_t *enc = (itb_encryptor_t *)0x1;
        ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", BAD_MODES[k], &enc),
                         ITB_BAD_INPUT);
        ck_assert_ptr_null(enc);
    }
    /* Sanity: 1 and 3 still succeed under the same inputs. */
    itb_encryptor_t *e1 = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &e1), ITB_OK);
    int mode = 0;
    ck_assert_int_eq(itb_encryptor_mode(e1, &mode), ITB_OK);
    ck_assert_int_eq(mode, 1);
    itb_encryptor_free(e1);

    itb_encryptor_t *e3 = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 3, &e3), ITB_OK);
    ck_assert_int_eq(itb_encryptor_mode(e3, &mode), ITB_OK);
    ck_assert_int_eq(mode, 3);
    itb_encryptor_free(e3);
}
END_TEST

int main(void)
{
    Suite *s = suite_create("easy_blake3");
    TCase *tc = tcase_create("core");
    tcase_set_timeout(tc, 60);
    tcase_add_test(tc, test_easy_blake3_roundtrip_across_nonce_sizes);
    tcase_add_test(tc, test_easy_blake3_triple_roundtrip_across_nonce_sizes);
    tcase_add_test(tc, test_easy_blake3_auth_across_nonce_sizes);
    tcase_add_test(tc, test_easy_blake3_triple_auth_across_nonce_sizes);
    tcase_add_test(tc, test_easy_blake3_persistence_across_nonce_sizes);
    tcase_add_test(tc, test_easy_blake3_roundtrip_sizes);
    tcase_add_test(tc, test_easy_blake3_default_mac_override);
    tcase_add_test(tc, test_easy_blake3_mode_rejection);
    suite_add_tcase(s, tc);

    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int failures = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failures == 0 ? 0 : 1;
}
