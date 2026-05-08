/*
 * test_blake2s.c — BLAKE2s-focused C binding coverage.
 *
 * Mirrors bindings/rust/tests/test_blake2s.rs one-to-one. BLAKE2s
 * ships at a single width (-256). Each Rust `#[test] fn` becomes a
 * single START_TEST / END_TEST block here; the cargo serial-lock
 * guard is implicit because each test_*.c file is built as its own
 * binary, giving per-process isolation against the libitb global
 * nonce-bits state.
 */

#include <check.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "itb.h"

static const struct { const char *name; int width; } BLAKE2S_HASHES[] = {
    {"blake2s", 256},
};
#define BLAKE2S_HASHES_COUNT (sizeof(BLAKE2S_HASHES) / sizeof(BLAKE2S_HASHES[0]))

static size_t expected_key_len(const char *name) {
    if (strcmp(name, "blake2s") == 0) return 32;
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

START_TEST(test_blake2s_roundtrip_across_nonce_sizes)
{
    int orig = itb_get_nonce_bits();
    size_t pt_len = 1024;
    uint8_t *plaintext = token_bytes(pt_len);

    for (size_t i = 0; i < NONCE_SIZES_COUNT; i++) {
        for (size_t j = 0; j < BLAKE2S_HASHES_COUNT; j++) {
            const char *hash_name = BLAKE2S_HASHES[j].name;
            ck_assert_int_eq(itb_set_nonce_bits(NONCE_SIZES[i]), ITB_OK);

            itb_seed_t *s0 = NULL, *s1 = NULL, *s2 = NULL;
            ck_assert_int_eq(itb_seed_new(hash_name, 1024, &s0), ITB_OK);
            ck_assert_int_eq(itb_seed_new(hash_name, 1024, &s1), ITB_OK);
            ck_assert_int_eq(itb_seed_new(hash_name, 1024, &s2), ITB_OK);

            uint8_t *ct = NULL; size_t ct_len = 0;
            ck_assert_int_eq(itb_encrypt(s0, s1, s2, plaintext, pt_len, &ct, &ct_len), ITB_OK);

            uint8_t *pt = NULL; size_t pt_out_len = 0;
            ck_assert_int_eq(itb_decrypt(s0, s1, s2, ct, ct_len, &pt, &pt_out_len), ITB_OK);
            ck_assert_uint_eq(pt_out_len, pt_len);
            ck_assert_mem_eq(pt, plaintext, pt_len);

            int hsize = itb_header_size();
            ck_assert_int_gt(hsize, 0);
            ck_assert_uint_ge(ct_len, (size_t)hsize);
            size_t chunk_len = 0;
            ck_assert_int_eq(itb_parse_chunk_len(ct, (size_t)hsize, &chunk_len), ITB_OK);
            ck_assert_uint_eq(chunk_len, ct_len);

            itb_buffer_free(ct);
            itb_buffer_free(pt);
            itb_seed_free(s0);
            itb_seed_free(s1);
            itb_seed_free(s2);
        }
    }
    free(plaintext);
    (void)itb_set_nonce_bits(orig);
}
END_TEST

START_TEST(test_blake2s_triple_roundtrip_across_nonce_sizes)
{
    int orig = itb_get_nonce_bits();
    size_t pt_len = 1024;
    uint8_t *plaintext = token_bytes(pt_len);

    for (size_t i = 0; i < NONCE_SIZES_COUNT; i++) {
        for (size_t j = 0; j < BLAKE2S_HASHES_COUNT; j++) {
            const char *hash_name = BLAKE2S_HASHES[j].name;
            ck_assert_int_eq(itb_set_nonce_bits(NONCE_SIZES[i]), ITB_OK);

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
    (void)itb_set_nonce_bits(orig);
}
END_TEST

START_TEST(test_blake2s_auth_across_nonce_sizes)
{
    int orig = itb_get_nonce_bits();
    size_t pt_len = 1024;
    uint8_t *plaintext = token_bytes(pt_len);

    for (size_t i = 0; i < NONCE_SIZES_COUNT; i++) {
        for (size_t m = 0; m < MAC_NAMES_COUNT; m++) {
            for (size_t j = 0; j < BLAKE2S_HASHES_COUNT; j++) {
                const char *hash_name = BLAKE2S_HASHES[j].name;
                ck_assert_int_eq(itb_set_nonce_bits(NONCE_SIZES[i]), ITB_OK);

                uint8_t *key = token_bytes(32);
                itb_mac_t *mac = NULL;
                ck_assert_int_eq(itb_mac_new(MAC_NAMES[m], key, 32, &mac), ITB_OK);

                itb_seed_t *s0 = NULL, *s1 = NULL, *s2 = NULL;
                ck_assert_int_eq(itb_seed_new(hash_name, 1024, &s0), ITB_OK);
                ck_assert_int_eq(itb_seed_new(hash_name, 1024, &s1), ITB_OK);
                ck_assert_int_eq(itb_seed_new(hash_name, 1024, &s2), ITB_OK);

                uint8_t *ct = NULL; size_t ct_len = 0;
                ck_assert_int_eq(itb_encrypt_auth(s0, s1, s2, mac,
                                                  plaintext, pt_len, &ct, &ct_len), ITB_OK);

                uint8_t *pt = NULL; size_t pt_out_len = 0;
                ck_assert_int_eq(itb_decrypt_auth(s0, s1, s2, mac,
                                                  ct, ct_len, &pt, &pt_out_len), ITB_OK);
                ck_assert_uint_eq(pt_out_len, pt_len);
                ck_assert_mem_eq(pt, plaintext, pt_len);

                size_t hsize = (size_t)itb_header_size();
                size_t end = hsize + 256;
                if (end > ct_len) end = ct_len;
                for (size_t b = hsize; b < end; b++) {
                    ct[b] ^= 0x01;
                }
                uint8_t *bad = NULL; size_t bad_len = 0;
                ck_assert_int_eq(itb_decrypt_auth(s0, s1, s2, mac, ct, ct_len,
                                                  &bad, &bad_len), ITB_MAC_FAILURE);
                ck_assert_ptr_null(bad);

                free(key);
                itb_buffer_free(ct);
                itb_buffer_free(pt);
                itb_seed_free(s0);
                itb_seed_free(s1);
                itb_seed_free(s2);
                itb_mac_free(mac);
            }
        }
    }
    free(plaintext);
    (void)itb_set_nonce_bits(orig);
}
END_TEST

START_TEST(test_blake2s_triple_auth_across_nonce_sizes)
{
    int orig = itb_get_nonce_bits();
    size_t pt_len = 1024;
    uint8_t *plaintext = token_bytes(pt_len);

    for (size_t i = 0; i < NONCE_SIZES_COUNT; i++) {
        for (size_t m = 0; m < MAC_NAMES_COUNT; m++) {
            for (size_t j = 0; j < BLAKE2S_HASHES_COUNT; j++) {
                const char *hash_name = BLAKE2S_HASHES[j].name;
                ck_assert_int_eq(itb_set_nonce_bits(NONCE_SIZES[i]), ITB_OK);

                uint8_t *key = token_bytes(32);
                itb_mac_t *mac = NULL;
                ck_assert_int_eq(itb_mac_new(MAC_NAMES[m], key, 32, &mac), ITB_OK);

                itb_seed_t *seeds[7] = {NULL};
                for (int k = 0; k < 7; k++) {
                    ck_assert_int_eq(itb_seed_new(hash_name, 1024, &seeds[k]), ITB_OK);
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

                size_t hsize = (size_t)itb_header_size();
                size_t end = hsize + 256;
                if (end > ct_len) end = ct_len;
                for (size_t b = hsize; b < end; b++) {
                    ct[b] ^= 0x01;
                }
                uint8_t *bad = NULL; size_t bad_len = 0;
                ck_assert_int_eq(itb_decrypt_auth_triple(seeds[0], seeds[1], seeds[2], seeds[3],
                                                         seeds[4], seeds[5], seeds[6], mac,
                                                         ct, ct_len, &bad, &bad_len), ITB_MAC_FAILURE);
                ck_assert_ptr_null(bad);

                free(key);
                itb_buffer_free(ct);
                itb_buffer_free(pt);
                for (int k = 0; k < 7; k++) itb_seed_free(seeds[k]);
                itb_mac_free(mac);
            }
        }
    }
    free(plaintext);
    (void)itb_set_nonce_bits(orig);
}
END_TEST

START_TEST(test_blake2s_persistence_across_nonce_sizes)
{
    int orig = itb_get_nonce_bits();
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

    for (size_t hi = 0; hi < BLAKE2S_HASHES_COUNT; hi++) {
        const char *hash_name = BLAKE2S_HASHES[hi].name;
        int width = BLAKE2S_HASHES[hi].width;
        const int candidate_kb[] = {512, 1024, 2048};
        for (size_t ki = 0; ki < sizeof(candidate_kb) / sizeof(candidate_kb[0]); ki++) {
            int kb = candidate_kb[ki];
            if (kb % width != 0) continue;
            for (size_t i = 0; i < NONCE_SIZES_COUNT; i++) {
                ck_assert_int_eq(itb_set_nonce_bits(NONCE_SIZES[i]), ITB_OK);

                itb_seed_t *ns = NULL, *ds = NULL, *ss = NULL;
                ck_assert_int_eq(itb_seed_new(hash_name, kb, &ns), ITB_OK);
                ck_assert_int_eq(itb_seed_new(hash_name, kb, &ds), ITB_OK);
                ck_assert_int_eq(itb_seed_new(hash_name, kb, &ss), ITB_OK);

                uint64_t ns_comps[32], ds_comps[32], ss_comps[32];
                size_t ns_cn = 0, ds_cn = 0, ss_cn = 0;
                ck_assert_int_eq(itb_seed_components(ns, ns_comps, 32, &ns_cn), ITB_OK);
                ck_assert_int_eq(itb_seed_components(ds, ds_comps, 32, &ds_cn), ITB_OK);
                ck_assert_int_eq(itb_seed_components(ss, ss_comps, 32, &ss_cn), ITB_OK);
                ck_assert_uint_eq(ns_cn * 64u, (size_t)kb);

                uint8_t ns_key[64], ds_key[64], ss_key[64];
                size_t ns_kl = 0, ds_kl = 0, ss_kl = 0;
                ck_assert_int_eq(itb_seed_hash_key(ns, ns_key, sizeof(ns_key), &ns_kl), ITB_OK);
                ck_assert_int_eq(itb_seed_hash_key(ds, ds_key, sizeof(ds_key), &ds_kl), ITB_OK);
                ck_assert_int_eq(itb_seed_hash_key(ss, ss_key, sizeof(ss_key), &ss_kl), ITB_OK);
                ck_assert_uint_eq(ns_kl, expected_key_len(hash_name));

                uint8_t *ct = NULL; size_t ct_len = 0;
                ck_assert_int_eq(itb_encrypt(ns, ds, ss, plaintext, pt_len, &ct, &ct_len), ITB_OK);
                itb_seed_free(ns);
                itb_seed_free(ds);
                itb_seed_free(ss);

                itb_seed_t *ns2 = NULL, *ds2 = NULL, *ss2 = NULL;
                ck_assert_int_eq(itb_seed_from_components(hash_name, ns_comps, ns_cn,
                                                          ns_key, ns_kl, &ns2), ITB_OK);
                ck_assert_int_eq(itb_seed_from_components(hash_name, ds_comps, ds_cn,
                                                          ds_key, ds_kl, &ds2), ITB_OK);
                ck_assert_int_eq(itb_seed_from_components(hash_name, ss_comps, ss_cn,
                                                          ss_key, ss_kl, &ss2), ITB_OK);

                uint8_t *pt = NULL; size_t pt_out_len = 0;
                ck_assert_int_eq(itb_decrypt(ns2, ds2, ss2, ct, ct_len, &pt, &pt_out_len), ITB_OK);
                ck_assert_uint_eq(pt_out_len, pt_len);
                ck_assert_mem_eq(pt, plaintext, pt_len);

                itb_buffer_free(ct);
                itb_buffer_free(pt);
                itb_seed_free(ns2);
                itb_seed_free(ds2);
                itb_seed_free(ss2);
            }
        }
    }
    free(plaintext);
    (void)itb_set_nonce_bits(orig);
}
END_TEST

START_TEST(test_blake2s_roundtrip_sizes)
{
    int orig = itb_get_nonce_bits();
    static const size_t SIZES[] = {1, 17, 4096, 65536, 1u << 20};
    for (size_t hi = 0; hi < BLAKE2S_HASHES_COUNT; hi++) {
        const char *hash_name = BLAKE2S_HASHES[hi].name;
        for (size_t i = 0; i < NONCE_SIZES_COUNT; i++) {
            for (size_t si = 0; si < sizeof(SIZES) / sizeof(SIZES[0]); si++) {
                size_t sz = SIZES[si];
                ck_assert_int_eq(itb_set_nonce_bits(NONCE_SIZES[i]), ITB_OK);
                uint8_t *plaintext = token_bytes(sz);

                itb_seed_t *ns = NULL, *ds = NULL, *ss = NULL;
                ck_assert_int_eq(itb_seed_new(hash_name, 1024, &ns), ITB_OK);
                ck_assert_int_eq(itb_seed_new(hash_name, 1024, &ds), ITB_OK);
                ck_assert_int_eq(itb_seed_new(hash_name, 1024, &ss), ITB_OK);

                uint8_t *ct = NULL; size_t ct_len = 0;
                ck_assert_int_eq(itb_encrypt(ns, ds, ss, plaintext, sz, &ct, &ct_len), ITB_OK);
                uint8_t *pt = NULL; size_t pt_out_len = 0;
                ck_assert_int_eq(itb_decrypt(ns, ds, ss, ct, ct_len, &pt, &pt_out_len), ITB_OK);
                ck_assert_uint_eq(pt_out_len, sz);
                ck_assert_mem_eq(pt, plaintext, sz);

                free(plaintext);
                itb_buffer_free(ct);
                itb_buffer_free(pt);
                itb_seed_free(ns);
                itb_seed_free(ds);
                itb_seed_free(ss);
            }
        }
    }
    (void)itb_set_nonce_bits(orig);
}
END_TEST

START_TEST(test_blake2s_invariants)
{
    /* Width invariant + per-primitive hash-key length contract + NULL
     * no-op contracts. The libitb primitive rejects zero-length
     * plaintext at the FFI layer (returns ITB_ENCRYPT_FAILED, not
     * ITB_OK), so the empty-roundtrip path is exercised as a
     * defined-rejection rather than a roundtrip. */
    for (size_t hi = 0; hi < BLAKE2S_HASHES_COUNT; hi++) {
        const char *hash_name = BLAKE2S_HASHES[hi].name;
        int expected_width = BLAKE2S_HASHES[hi].width;
        itb_seed_t *ns = NULL, *ds = NULL, *ss = NULL;
        ck_assert_int_eq(itb_seed_new(hash_name, 1024, &ns), ITB_OK);
        ck_assert_int_eq(itb_seed_new(hash_name, 1024, &ds), ITB_OK);
        ck_assert_int_eq(itb_seed_new(hash_name, 1024, &ss), ITB_OK);

        int width = 0;
        ck_assert_int_eq(itb_seed_width(ns, &width), ITB_OK);
        ck_assert_int_eq(width, expected_width);

        uint8_t key[128];
        size_t kl = 0;
        ck_assert_int_eq(itb_seed_hash_key(ns, key, sizeof(key), &kl), ITB_OK);
        ck_assert_uint_eq(kl, expected_key_len(hash_name));

        uint8_t *ct = (uint8_t *)0x1; size_t ct_len = 99;
        itb_status_t rc = itb_encrypt(ns, ds, ss, NULL, 0, &ct, &ct_len);
        ck_assert_int_eq(rc, ITB_ENCRYPT_FAILED);
        ck_assert_ptr_null(ct);
        ck_assert_uint_eq(ct_len, 0);

        itb_buffer_free(NULL);
        itb_seed_free(NULL);
        itb_mac_free(NULL);

        itb_seed_free(ns);
        itb_seed_free(ds);
        itb_seed_free(ss);
    }
}
END_TEST

int main(void)
{
    Suite *s = suite_create("blake2s");
    TCase *tc = tcase_create("core");
    tcase_set_timeout(tc, 60);
    tcase_add_test(tc, test_blake2s_roundtrip_across_nonce_sizes);
    tcase_add_test(tc, test_blake2s_triple_roundtrip_across_nonce_sizes);
    tcase_add_test(tc, test_blake2s_auth_across_nonce_sizes);
    tcase_add_test(tc, test_blake2s_triple_auth_across_nonce_sizes);
    tcase_add_test(tc, test_blake2s_persistence_across_nonce_sizes);
    tcase_add_test(tc, test_blake2s_roundtrip_sizes);
    tcase_add_test(tc, test_blake2s_invariants);
    suite_add_tcase(s, tc);

    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int failures = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failures == 0 ? 0 : 1;
}
