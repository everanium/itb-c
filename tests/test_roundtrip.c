/*
 * test_roundtrip.c — generic Seed / MAC / cipher round-trip coverage.
 *
 * Mirrors bindings/rust/tests/test_roundtrip.rs one-to-one. Confirms
 * the Seed, MAC, and low-level encrypt / decrypt entry points
 * round-trip plaintext correctly across every primitive in the
 * canonical FFI registry × the three ITB key-bit widths (512 / 1024 /
 * 2048) that are valid for each native hash width. Covers Single,
 * Triple, and Authenticated variants plus the version / list_hashes /
 * constants probes.
 */

#include <check.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "itb.h"

static const uint8_t PLAINTEXT[] =
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
#define PLAINTEXT_LEN (sizeof(PLAINTEXT) - 1)

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

static uint8_t *pseudo_payload(size_t n) {
    uint8_t *p = (uint8_t *) malloc(n == 0 ? 1 : n);
    ck_assert_ptr_nonnull(p);
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t) (((i * 17u) + 5u) & 0xffu);
    }
    return p;
}

START_TEST(test_roundtrip_single_blake3)
{
    itb_seed_t *n = NULL, *d = NULL, *s = NULL;
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &n), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &d), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &s), ITB_OK);

    uint8_t *ct = NULL; size_t ct_len = 0;
    ck_assert_int_eq(itb_encrypt(n, d, s, PLAINTEXT, PLAINTEXT_LEN, &ct, &ct_len), ITB_OK);
    /* Ciphertext must differ from plaintext both in length and in
     * bytes — assert length grew (ITB containerises plaintext into a
     * larger pixel grid). */
    ck_assert_uint_gt(ct_len, PLAINTEXT_LEN);

    uint8_t *pt = NULL; size_t pt_len = 0;
    ck_assert_int_eq(itb_decrypt(n, d, s, ct, ct_len, &pt, &pt_len), ITB_OK);
    ck_assert_uint_eq(pt_len, PLAINTEXT_LEN);
    ck_assert_mem_eq(pt, PLAINTEXT, PLAINTEXT_LEN);

    itb_buffer_free(ct);
    itb_buffer_free(pt);
    itb_seed_free(n);
    itb_seed_free(d);
    itb_seed_free(s);
}
END_TEST

START_TEST(test_roundtrip_triple_blake3)
{
    itb_seed_t *seeds[7] = {NULL};
    for (int k = 0; k < 7; k++) {
        ck_assert_int_eq(itb_seed_new("blake3", 1024, &seeds[k]), ITB_OK);
    }

    uint8_t *ct = NULL; size_t ct_len = 0;
    ck_assert_int_eq(itb_encrypt_triple(seeds[0], seeds[1], seeds[2], seeds[3],
                                        seeds[4], seeds[5], seeds[6],
                                        PLAINTEXT, PLAINTEXT_LEN, &ct, &ct_len), ITB_OK);
    uint8_t *pt = NULL; size_t pt_len = 0;
    ck_assert_int_eq(itb_decrypt_triple(seeds[0], seeds[1], seeds[2], seeds[3],
                                        seeds[4], seeds[5], seeds[6],
                                        ct, ct_len, &pt, &pt_len), ITB_OK);
    ck_assert_uint_eq(pt_len, PLAINTEXT_LEN);
    ck_assert_mem_eq(pt, PLAINTEXT, PLAINTEXT_LEN);

    itb_buffer_free(ct);
    itb_buffer_free(pt);
    for (int k = 0; k < 7; k++) itb_seed_free(seeds[k]);
}
END_TEST

START_TEST(test_roundtrip_auth_hmac_sha256)
{
    itb_seed_t *n = NULL, *d = NULL, *s = NULL;
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &n), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &d), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &s), ITB_OK);

    uint8_t key[32];
    memset(key, 0x42, sizeof(key));
    itb_mac_t *mac = NULL;
    ck_assert_int_eq(itb_mac_new("hmac-sha256", key, sizeof(key), &mac), ITB_OK);

    uint8_t *ct = NULL; size_t ct_len = 0;
    ck_assert_int_eq(itb_encrypt_auth(n, d, s, mac,
                                      PLAINTEXT, PLAINTEXT_LEN, &ct, &ct_len), ITB_OK);
    uint8_t *pt = NULL; size_t pt_len = 0;
    ck_assert_int_eq(itb_decrypt_auth(n, d, s, mac,
                                      ct, ct_len, &pt, &pt_len), ITB_OK);
    ck_assert_uint_eq(pt_len, PLAINTEXT_LEN);
    ck_assert_mem_eq(pt, PLAINTEXT, PLAINTEXT_LEN);

    itb_buffer_free(ct);
    itb_buffer_free(pt);
    itb_seed_free(n);
    itb_seed_free(d);
    itb_seed_free(s);
    itb_mac_free(mac);
}
END_TEST

START_TEST(test_roundtrip_auth_triple_kmac256)
{
    itb_seed_t *seeds[7] = {NULL};
    for (int k = 0; k < 7; k++) {
        ck_assert_int_eq(itb_seed_new("blake3", 1024, &seeds[k]), ITB_OK);
    }
    uint8_t key[32];
    memset(key, 0x21, sizeof(key));
    itb_mac_t *mac = NULL;
    ck_assert_int_eq(itb_mac_new("kmac256", key, sizeof(key), &mac), ITB_OK);

    uint8_t *ct = NULL; size_t ct_len = 0;
    ck_assert_int_eq(itb_encrypt_auth_triple(seeds[0], seeds[1], seeds[2], seeds[3],
                                             seeds[4], seeds[5], seeds[6], mac,
                                             PLAINTEXT, PLAINTEXT_LEN, &ct, &ct_len), ITB_OK);
    uint8_t *pt = NULL; size_t pt_len = 0;
    ck_assert_int_eq(itb_decrypt_auth_triple(seeds[0], seeds[1], seeds[2], seeds[3],
                                             seeds[4], seeds[5], seeds[6], mac,
                                             ct, ct_len, &pt, &pt_len), ITB_OK);
    ck_assert_uint_eq(pt_len, PLAINTEXT_LEN);
    ck_assert_mem_eq(pt, PLAINTEXT, PLAINTEXT_LEN);

    itb_buffer_free(ct);
    itb_buffer_free(pt);
    for (int k = 0; k < 7; k++) itb_seed_free(seeds[k]);
    itb_mac_free(mac);
}
END_TEST

START_TEST(test_roundtrip_seed_components_roundtrip)
{
    itb_seed_t *s = NULL;
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &s), ITB_OK);
    uint64_t comps[32]; size_t cn = 0;
    ck_assert_int_eq(itb_seed_components(s, comps, 32, &cn), ITB_OK);
    uint8_t key[64]; size_t kl = 0;
    ck_assert_int_eq(itb_seed_hash_key(s, key, sizeof(key), &kl), ITB_OK);

    itb_seed_t *s2 = NULL;
    ck_assert_int_eq(itb_seed_from_components("blake3", comps, cn, key, kl, &s2), ITB_OK);

    uint64_t comps2[32]; size_t cn2 = 0;
    ck_assert_int_eq(itb_seed_components(s2, comps2, 32, &cn2), ITB_OK);
    ck_assert_uint_eq(cn2, cn);
    ck_assert_mem_eq(comps2, comps, cn * sizeof(uint64_t));

    uint8_t key2[64]; size_t kl2 = 0;
    ck_assert_int_eq(itb_seed_hash_key(s2, key2, sizeof(key2), &kl2), ITB_OK);
    ck_assert_uint_eq(kl2, kl);
    ck_assert_mem_eq(key2, key, kl);

    itb_seed_free(s);
    itb_seed_free(s2);
}
END_TEST

START_TEST(test_roundtrip_auth_decrypt_tampered_fails_with_mac_failure)
{
    itb_seed_t *n = NULL, *d = NULL, *s = NULL;
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &n), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &d), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &s), ITB_OK);

    uint8_t key[32] = {0};
    itb_mac_t *mac = NULL;
    ck_assert_int_eq(itb_mac_new("hmac-sha256", key, sizeof(key), &mac), ITB_OK);

    uint8_t *ct = NULL; size_t ct_len = 0;
    ck_assert_int_eq(itb_encrypt_auth(n, d, s, mac,
                                      PLAINTEXT, PLAINTEXT_LEN, &ct, &ct_len), ITB_OK);
    /* Flip the last byte to tamper with the MAC tag. */
    ct[ct_len - 1] ^= 0xff;
    uint8_t *bad = NULL; size_t bad_len = 0;
    ck_assert_int_eq(itb_decrypt_auth(n, d, s, mac,
                                      ct, ct_len, &bad, &bad_len),
                     ITB_MAC_FAILURE);
    ck_assert_ptr_null(bad);

    itb_buffer_free(ct);
    itb_seed_free(n);
    itb_seed_free(d);
    itb_seed_free(s);
    itb_mac_free(mac);
}
END_TEST

START_TEST(test_roundtrip_seed_free_does_not_panic)
{
    /* Construct + free in a tight loop; the free path must not double-free. */
    for (int i = 0; i < 32; i++) {
        itb_seed_t *seed = NULL;
        ck_assert_int_eq(itb_seed_new("blake3", 512, &seed), ITB_OK);
        itb_seed_free(seed);
    }
    /* Idempotent NULL-free contract. */
    itb_seed_free(NULL);
}
END_TEST

START_TEST(test_roundtrip_version)
{
    /* Two-call probe: discover required size first. */
    size_t needed = 0;
    itb_status_t rc = itb_version(NULL, 0, &needed);
    ck_assert_int_eq(rc, ITB_BUFFER_TOO_SMALL);
    ck_assert_uint_gt(needed, 0);

    char *buf = (char *) malloc(needed + 1);
    ck_assert_ptr_nonnull(buf);
    size_t got = 0;
    ck_assert_int_eq(itb_version(buf, needed + 1, &got), ITB_OK);
    ck_assert_uint_eq(got, needed);
    /* SemVer-ish "<digits>.<digits>.<digits>" prefix. */
    char *first_dot = strchr(buf, '.');
    ck_assert_ptr_nonnull(first_dot);
    char *second_dot = strchr(first_dot + 1, '.');
    ck_assert_ptr_nonnull(second_dot);
    for (char *p = buf; p < first_dot; p++) {
        ck_assert(isdigit((unsigned char) *p));
    }
    for (char *p = first_dot + 1; p < second_dot; p++) {
        ck_assert(isdigit((unsigned char) *p));
    }
    ck_assert(isdigit((unsigned char) *(second_dot + 1)));

    free(buf);
}
END_TEST

START_TEST(test_roundtrip_list_hashes)
{
    int got = itb_hash_count();
    ck_assert_int_eq(got, (int) CANONICAL_HASHES_COUNT);
    for (size_t i = 0; i < CANONICAL_HASHES_COUNT; i++) {
        char buf[64]; size_t len = 0;
        ck_assert_int_eq(itb_hash_name((int) i, buf, sizeof(buf), &len), ITB_OK);
        ck_assert_str_eq(buf, CANONICAL_HASHES[i].name);
        ck_assert_int_eq(itb_hash_width((int) i), CANONICAL_HASHES[i].width);
    }
}
END_TEST

START_TEST(test_roundtrip_constants)
{
    ck_assert_int_eq(itb_max_key_bits(), 2048);
    ck_assert_int_eq(itb_channels(), 8);
}
END_TEST

START_TEST(test_roundtrip_new_and_free)
{
    itb_seed_t *s = NULL;
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &s), ITB_OK);
    ck_assert_ptr_nonnull(s);
    char name[64]; size_t name_len = 0;
    ck_assert_int_eq(itb_seed_hash_name(s, name, sizeof(name), &name_len), ITB_OK);
    ck_assert_str_eq(name, "blake3");
    int width = 0;
    ck_assert_int_eq(itb_seed_width(s, &width), ITB_OK);
    ck_assert_int_eq(width, 256);
    itb_seed_free(s);
}
END_TEST

START_TEST(test_roundtrip_bad_hash)
{
    itb_seed_t *s = NULL;
    itb_status_t rc = itb_seed_new("nonsense-hash", 1024, &s);
    ck_assert_int_eq(rc, ITB_BAD_HASH);
    ck_assert_ptr_null(s);
}
END_TEST

START_TEST(test_roundtrip_bad_key_bits)
{
    static const int BAD[] = {0, 256, 511, 2049};
    for (size_t i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++) {
        itb_seed_t *s = NULL;
        itb_status_t rc = itb_seed_new("blake3", BAD[i], &s);
        ck_assert_int_eq(rc, ITB_BAD_KEY_BITS);
        ck_assert_ptr_null(s);
    }
}
END_TEST

START_TEST(test_roundtrip_all_hashes_all_widths_single)
{
    size_t pt_len = 4096;
    uint8_t *plaintext = pseudo_payload(pt_len);

    for (size_t hi = 0; hi < CANONICAL_HASHES_COUNT; hi++) {
        const char *name = CANONICAL_HASHES[hi].name;
        static const int KEY_BITS[] = {512, 1024, 2048};
        for (size_t ki = 0; ki < sizeof(KEY_BITS) / sizeof(KEY_BITS[0]); ki++) {
            int kb = KEY_BITS[ki];
            itb_seed_t *ns = NULL, *ds = NULL, *ss = NULL;
            ck_assert_int_eq(itb_seed_new(name, kb, &ns), ITB_OK);
            ck_assert_int_eq(itb_seed_new(name, kb, &ds), ITB_OK);
            ck_assert_int_eq(itb_seed_new(name, kb, &ss), ITB_OK);

            uint8_t *ct = NULL; size_t ct_len = 0;
            ck_assert_int_eq(itb_encrypt(ns, ds, ss, plaintext, pt_len, &ct, &ct_len), ITB_OK);
            ck_assert_uint_gt(ct_len, pt_len);
            uint8_t *pt = NULL; size_t pt_out_len = 0;
            ck_assert_int_eq(itb_decrypt(ns, ds, ss, ct, ct_len, &pt, &pt_out_len), ITB_OK);
            ck_assert_uint_eq(pt_out_len, pt_len);
            ck_assert_mem_eq(pt, plaintext, pt_len);

            itb_buffer_free(ct);
            itb_buffer_free(pt);
            itb_seed_free(ns);
            itb_seed_free(ds);
            itb_seed_free(ss);
        }
    }
    free(plaintext);
}
END_TEST

START_TEST(test_roundtrip_seed_width_mismatch)
{
    itb_seed_t *ns = NULL, *ds = NULL, *ss = NULL;
    ck_assert_int_eq(itb_seed_new("siphash24", 1024, &ns), ITB_OK); /* width 128 */
    ck_assert_int_eq(itb_seed_new("blake3",    1024, &ds), ITB_OK); /* width 256 */
    ck_assert_int_eq(itb_seed_new("blake3",    1024, &ss), ITB_OK); /* width 256 */

    static const uint8_t pt[] = "hello";
    uint8_t *ct = NULL; size_t ct_len = 0;
    itb_status_t rc = itb_encrypt(ns, ds, ss, pt, sizeof(pt) - 1, &ct, &ct_len);
    ck_assert_int_eq(rc, ITB_SEED_WIDTH_MIX);
    ck_assert_ptr_null(ct);

    itb_seed_free(ns);
    itb_seed_free(ds);
    itb_seed_free(ss);
}
END_TEST

START_TEST(test_roundtrip_all_hashes_all_widths_triple)
{
    size_t pt_len = 4096;
    uint8_t *plaintext = pseudo_payload(pt_len);

    for (size_t hi = 0; hi < CANONICAL_HASHES_COUNT; hi++) {
        const char *name = CANONICAL_HASHES[hi].name;
        static const int KEY_BITS[] = {512, 1024, 2048};
        for (size_t ki = 0; ki < sizeof(KEY_BITS) / sizeof(KEY_BITS[0]); ki++) {
            int kb = KEY_BITS[ki];
            itb_seed_t *seeds[7] = {NULL};
            for (int k = 0; k < 7; k++) {
                ck_assert_int_eq(itb_seed_new(name, kb, &seeds[k]), ITB_OK);
            }

            uint8_t *ct = NULL; size_t ct_len = 0;
            ck_assert_int_eq(itb_encrypt_triple(seeds[0], seeds[1], seeds[2], seeds[3],
                                                seeds[4], seeds[5], seeds[6],
                                                plaintext, pt_len, &ct, &ct_len), ITB_OK);
            ck_assert_uint_gt(ct_len, pt_len);
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
}
END_TEST

START_TEST(test_roundtrip_triple_seed_width_mismatch)
{
    /* One width-128 seed mixed with six width-256 seeds. */
    itb_seed_t *odd = NULL;
    ck_assert_int_eq(itb_seed_new("siphash24", 1024, &odd), ITB_OK);
    itb_seed_t *r[6] = {NULL};
    for (int k = 0; k < 6; k++) {
        ck_assert_int_eq(itb_seed_new("blake3", 1024, &r[k]), ITB_OK);
    }
    static const uint8_t pt[] = "hello";
    uint8_t *ct = NULL; size_t ct_len = 0;
    itb_status_t rc = itb_encrypt_triple(odd, r[0], r[1], r[2], r[3], r[4], r[5],
                                         pt, sizeof(pt) - 1, &ct, &ct_len);
    ck_assert_int_eq(rc, ITB_SEED_WIDTH_MIX);
    ck_assert_ptr_null(ct);

    itb_seed_free(odd);
    for (int k = 0; k < 6; k++) itb_seed_free(r[k]);
}
END_TEST

int main(void)
{
    Suite *s = suite_create("roundtrip");
    TCase *tc = tcase_create("core");
    tcase_set_timeout(tc, 180);
    tcase_add_test(tc, test_roundtrip_single_blake3);
    tcase_add_test(tc, test_roundtrip_triple_blake3);
    tcase_add_test(tc, test_roundtrip_auth_hmac_sha256);
    tcase_add_test(tc, test_roundtrip_auth_triple_kmac256);
    tcase_add_test(tc, test_roundtrip_seed_components_roundtrip);
    tcase_add_test(tc, test_roundtrip_auth_decrypt_tampered_fails_with_mac_failure);
    tcase_add_test(tc, test_roundtrip_seed_free_does_not_panic);
    tcase_add_test(tc, test_roundtrip_version);
    tcase_add_test(tc, test_roundtrip_list_hashes);
    tcase_add_test(tc, test_roundtrip_constants);
    tcase_add_test(tc, test_roundtrip_new_and_free);
    tcase_add_test(tc, test_roundtrip_bad_hash);
    tcase_add_test(tc, test_roundtrip_bad_key_bits);
    tcase_add_test(tc, test_roundtrip_all_hashes_all_widths_single);
    tcase_add_test(tc, test_roundtrip_seed_width_mismatch);
    tcase_add_test(tc, test_roundtrip_all_hashes_all_widths_triple);
    tcase_add_test(tc, test_roundtrip_triple_seed_width_mismatch);
    suite_add_tcase(s, tc);

    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int failures = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failures == 0 ? 0 : 1;
}
