/*
 * test_persistence.c — cross-process persistence round-trip tests.
 *
 * Mirrors bindings/rust/tests/test_persistence.rs one-to-one. Exercises
 * the itb_seed_components / itb_seed_hash_key / itb_seed_from_components
 * surface across every primitive in the registry × the three ITB key-bit
 * widths (512 / 1024 / 2048) that are valid for each native hash width.
 *
 * Without both `components` and `hash_key` captured at encrypt-side and
 * re-supplied at decrypt-side, the seed state cannot be reconstructed
 * and the ciphertext is unreadable.
 */

#include <check.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "itb.h"

static const struct { const char *name; int width; } CANONICAL_HASHES[] = {
    {"areion256",  256},
    {"areion512",  512},
    {"siphash24",  128},
    {"aescmac",    128},
    {"blake2b256", 256},
    {"blake2b512", 512},
    {"blake2s",    256},
    {"blake3",     256},
    {"chacha20",   256},
};
#define CANONICAL_HASHES_COUNT (sizeof(CANONICAL_HASHES) / sizeof(CANONICAL_HASHES[0]))

/* Maps a primitive name to its expected fixed hash-key length in
 * bytes. SipHash-2-4 has no internal fixed key (its keying material is
 * the seed components themselves), so the expected length is 0. */
static size_t expected_hash_key_len(const char *name)
{
    if (strcmp(name, "areion256") == 0) return 32;
    if (strcmp(name, "areion512") == 0) return 64;
    if (strcmp(name, "siphash24") == 0) return 0;
    if (strcmp(name, "aescmac")   == 0) return 16;
    if (strcmp(name, "blake2b256") == 0) return 32;
    if (strcmp(name, "blake2b512") == 0) return 64;
    if (strcmp(name, "blake2s")   == 0) return 32;
    if (strcmp(name, "blake3")    == 0) return 32;
    if (strcmp(name, "chacha20")  == 0) return 32;
    ck_abort_msg("unexpected primitive %s", name);
    return 0;
}

/* Builds the test plaintext (binary data including 0x00 bytes). */
static uint8_t *build_plaintext(size_t *out_len)
{
    static const char prefix[] = "any binary data, including 0x00 bytes -- ";
    size_t prefix_len = sizeof(prefix) - 1;
    size_t total = prefix_len + 256;
    uint8_t *p = (uint8_t *) malloc(total);
    ck_assert_ptr_nonnull(p);
    memcpy(p, prefix, prefix_len);
    for (size_t i = 0; i < 256; i++) {
        p[prefix_len + i] = (uint8_t) i;
    }
    *out_len = total;
    return p;
}

START_TEST(test_persistence_roundtrip_all_hashes)
{
    size_t pt_len = 0;
    uint8_t *plaintext = build_plaintext(&pt_len);

    for (size_t hi = 0; hi < CANONICAL_HASHES_COUNT; hi++) {
        const char *name = CANONICAL_HASHES[hi].name;
        int width = CANONICAL_HASHES[hi].width;
        static const int CANDIDATE_KB[] = {512, 1024, 2048};
        for (size_t ki = 0; ki < sizeof(CANDIDATE_KB) / sizeof(CANDIDATE_KB[0]); ki++) {
            int kb = CANDIDATE_KB[ki];
            if (kb % width != 0) continue;

            /* Day 1 — random seeds. */
            itb_seed_t *ns = NULL, *ds = NULL, *ss = NULL;
            ck_assert_int_eq(itb_seed_new(name, kb, &ns), ITB_OK);
            ck_assert_int_eq(itb_seed_new(name, kb, &ds), ITB_OK);
            ck_assert_int_eq(itb_seed_new(name, kb, &ss), ITB_OK);

            uint64_t ns_comps[32], ds_comps[32], ss_comps[32];
            size_t ns_cn = 0, ds_cn = 0, ss_cn = 0;
            ck_assert_int_eq(itb_seed_components(ns, ns_comps, 32, &ns_cn), ITB_OK);
            ck_assert_int_eq(itb_seed_components(ds, ds_comps, 32, &ds_cn), ITB_OK);
            ck_assert_int_eq(itb_seed_components(ss, ss_comps, 32, &ss_cn), ITB_OK);
            ck_assert_uint_eq(ns_cn * 64u, (size_t) kb);

            uint8_t ns_key[64], ds_key[64], ss_key[64];
            size_t ns_kl = 0, ds_kl = 0, ss_kl = 0;
            ck_assert_int_eq(itb_seed_hash_key(ns, ns_key, sizeof(ns_key), &ns_kl), ITB_OK);
            ck_assert_int_eq(itb_seed_hash_key(ds, ds_key, sizeof(ds_key), &ds_kl), ITB_OK);
            ck_assert_int_eq(itb_seed_hash_key(ss, ss_key, sizeof(ss_key), &ss_kl), ITB_OK);
            ck_assert_uint_eq(ns_kl, expected_hash_key_len(name));

            uint8_t *ct = NULL; size_t ct_len = 0;
            ck_assert_int_eq(itb_encrypt(ns, ds, ss, plaintext, pt_len, &ct, &ct_len), ITB_OK);
            itb_seed_free(ns);
            itb_seed_free(ds);
            itb_seed_free(ss);

            /* Day 2 — restore from saved material. */
            itb_seed_t *ns2 = NULL, *ds2 = NULL, *ss2 = NULL;
            ck_assert_int_eq(itb_seed_from_components(name, ns_comps, ns_cn,
                                                      ns_key, ns_kl, &ns2), ITB_OK);
            ck_assert_int_eq(itb_seed_from_components(name, ds_comps, ds_cn,
                                                      ds_key, ds_kl, &ds2), ITB_OK);
            ck_assert_int_eq(itb_seed_from_components(name, ss_comps, ss_cn,
                                                      ss_key, ss_kl, &ss2), ITB_OK);

            uint8_t *pt = NULL; size_t pt_out_len = 0;
            ck_assert_int_eq(itb_decrypt(ns2, ds2, ss2, ct, ct_len, &pt, &pt_out_len), ITB_OK);
            ck_assert_uint_eq(pt_out_len, pt_len);
            ck_assert_mem_eq(pt, plaintext, pt_len);

            /* Restored seeds report the same components + key. */
            uint64_t ns2_comps[32]; size_t ns2_cn = 0;
            ck_assert_int_eq(itb_seed_components(ns2, ns2_comps, 32, &ns2_cn), ITB_OK);
            ck_assert_uint_eq(ns2_cn, ns_cn);
            ck_assert_mem_eq(ns2_comps, ns_comps, ns_cn * sizeof(uint64_t));

            uint8_t ns2_key[64]; size_t ns2_kl = 0;
            ck_assert_int_eq(itb_seed_hash_key(ns2, ns2_key, sizeof(ns2_key), &ns2_kl), ITB_OK);
            ck_assert_uint_eq(ns2_kl, ns_kl);
            ck_assert_mem_eq(ns2_key, ns_key, ns_kl);

            itb_buffer_free(ct);
            itb_buffer_free(pt);
            itb_seed_free(ns2);
            itb_seed_free(ds2);
            itb_seed_free(ss2);
        }
    }
    free(plaintext);
}
END_TEST

START_TEST(test_persistence_random_key_path)
{
    /* 512-bit zero components — sufficient for non-SipHash primitives. */
    uint64_t components[8] = {0};
    for (size_t hi = 0; hi < CANONICAL_HASHES_COUNT; hi++) {
        const char *name = CANONICAL_HASHES[hi].name;
        itb_seed_t *seed = NULL;
        ck_assert_int_eq(itb_seed_from_components(name, components, 8,
                                                  NULL, 0, &seed), ITB_OK);
        uint8_t key[64]; size_t kl = 0;
        ck_assert_int_eq(itb_seed_hash_key(seed, key, sizeof(key), &kl), ITB_OK);
        if (strcmp(name, "siphash24") == 0) {
            ck_assert_uint_eq(kl, 0);
        } else {
            ck_assert_uint_eq(kl, expected_hash_key_len(name));
        }
        itb_seed_free(seed);
    }
}
END_TEST

START_TEST(test_persistence_explicit_key_preserved)
{
    /* BLAKE3 has a 32-byte symmetric key. */
    uint8_t explicit_key[32];
    for (uint8_t i = 0; i < 32; i++) explicit_key[i] = i;
    uint64_t components[8];
    for (int i = 0; i < 8; i++) components[i] = 0xCAFEBABEDEADBEEFULL;

    itb_seed_t *seed = NULL;
    ck_assert_int_eq(itb_seed_from_components("blake3", components, 8,
                                              explicit_key, sizeof(explicit_key),
                                              &seed), ITB_OK);
    uint8_t key[32]; size_t kl = 0;
    ck_assert_int_eq(itb_seed_hash_key(seed, key, sizeof(key), &kl), ITB_OK);
    ck_assert_uint_eq(kl, sizeof(explicit_key));
    ck_assert_mem_eq(key, explicit_key, kl);
    itb_seed_free(seed);
}
END_TEST

START_TEST(test_persistence_bad_key_size)
{
    /* A non-empty hash_key whose length does not match the primitive's
     * expected length must surface a clean error (no panic across the
     * FFI). Seven bytes is wrong for blake3 (expects 32). */
    uint64_t components[16] = {0};
    uint8_t bad_key[7] = {0};
    itb_seed_t *seed = NULL;
    itb_status_t rc = itb_seed_from_components("blake3", components, 16,
                                               bad_key, sizeof(bad_key), &seed);
    ck_assert_int_ne(rc, ITB_OK);
    ck_assert_ptr_null(seed);
}
END_TEST

START_TEST(test_persistence_siphash_rejects_hash_key)
{
    /* SipHash-2-4 takes no internal fixed key; passing one must be
     * rejected (not silently ignored). */
    uint64_t components[8] = {0};
    uint8_t nonempty[16] = {0};
    itb_seed_t *seed = NULL;
    itb_status_t rc = itb_seed_from_components("siphash24", components, 8,
                                               nonempty, sizeof(nonempty), &seed);
    ck_assert_int_ne(rc, ITB_OK);
    ck_assert_ptr_null(seed);
}
END_TEST

int main(void)
{
    Suite *s = suite_create("persistence");
    TCase *tc = tcase_create("core");
    tcase_set_timeout(tc, 120);
    tcase_add_test(tc, test_persistence_roundtrip_all_hashes);
    tcase_add_test(tc, test_persistence_random_key_path);
    tcase_add_test(tc, test_persistence_explicit_key_preserved);
    tcase_add_test(tc, test_persistence_bad_key_size);
    tcase_add_test(tc, test_persistence_siphash_rejects_hash_key);
    suite_add_tcase(s, tc);

    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int failures = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failures == 0 ? 0 : 1;
}
