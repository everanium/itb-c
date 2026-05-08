/*
 * test_auth.c — end-to-end authenticated-encryption coverage for the
 * C binding.
 *
 * Mirrors bindings/rust/tests/test_auth.rs one-to-one. Exercises the
 * 3 MACs × 3 hash widths × {Single, Triple} round-trip plus tamper
 * rejection at the dynamic header offset and cross-MAC rejection.
 *
 * Per-binary fork() isolation gives each test its own libitb
 * process-globals; no in-process serial lock is needed.
 */

#include <check.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "itb.h"

/* (name, key_size, tag_size, min_key_bytes) — canonical FFI registry. */
static const struct {
    const char *name;
    int key_size;
    int tag_size;
    int min_key_bytes;
} CANONICAL_MACS[] = {
    {"kmac256",     32, 32, 16},
    {"hmac-sha256", 32, 32, 16},
    {"hmac-blake3", 32, 32, 32},
};
#define CANONICAL_MACS_COUNT (sizeof(CANONICAL_MACS) / sizeof(CANONICAL_MACS[0]))

/* (hash, native width) representatives — one per ITB key-width axis. */
static const struct { const char *name; int width; } HASH_BY_WIDTH[] = {
    {"siphash24",  128},
    {"blake3",     256},
    {"blake2b512", 512},
};
#define HASH_BY_WIDTH_COUNT (sizeof(HASH_BY_WIDTH) / sizeof(HASH_BY_WIDTH[0]))

static const uint8_t KEY_BYTES[32] = {
    0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,
    0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,
    0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,
    0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,
};

static uint8_t *pseudo_plaintext(size_t n) {
    uint8_t *p = (uint8_t *) malloc(n == 0 ? 1 : n);
    ck_assert_ptr_nonnull(p);
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t) (i & 0xff);
    }
    return p;
}

START_TEST(test_auth_list_macs)
{
    int got_count = itb_mac_count();
    ck_assert_int_eq(got_count, (int) CANONICAL_MACS_COUNT);
    for (size_t i = 0; i < CANONICAL_MACS_COUNT; i++) {
        char buf[64];
        size_t name_len = 0;
        ck_assert_int_eq(itb_mac_name((int) i, buf, sizeof(buf), &name_len), ITB_OK);
        ck_assert_str_eq(buf, CANONICAL_MACS[i].name);
        ck_assert_int_eq(itb_mac_key_size((int) i), CANONICAL_MACS[i].key_size);
        ck_assert_int_eq(itb_mac_tag_size((int) i), CANONICAL_MACS[i].tag_size);
        ck_assert_int_eq(itb_mac_min_key_bytes((int) i), CANONICAL_MACS[i].min_key_bytes);
    }
}
END_TEST

START_TEST(test_auth_create_and_free)
{
    for (size_t i = 0; i < CANONICAL_MACS_COUNT; i++) {
        itb_mac_t *m = NULL;
        ck_assert_int_eq(itb_mac_new(CANONICAL_MACS[i].name,
                                     KEY_BYTES, sizeof(KEY_BYTES), &m), ITB_OK);
        ck_assert_ptr_nonnull(m);
        itb_mac_free(m);
    }
}
END_TEST

START_TEST(test_auth_mac_free_release)
{
    /* Construct + free in a tight loop; the free path must not double-free
     * or leak. A use-after-free in libitb would surface as a crash. */
    for (int i = 0; i < 32; i++) {
        itb_mac_t *m = NULL;
        ck_assert_int_eq(itb_mac_new("hmac-sha256",
                                     KEY_BYTES, sizeof(KEY_BYTES), &m), ITB_OK);
        itb_mac_free(m);
    }
    /* Idempotent NULL-free contract. */
    itb_mac_free(NULL);
}
END_TEST

START_TEST(test_auth_bad_name)
{
    itb_mac_t *m = NULL;
    itb_status_t rc = itb_mac_new("nonsense-mac", KEY_BYTES, sizeof(KEY_BYTES), &m);
    ck_assert_int_eq(rc, ITB_BAD_MAC);
    ck_assert_ptr_null(m);
}
END_TEST

START_TEST(test_auth_short_key)
{
    for (size_t i = 0; i < CANONICAL_MACS_COUNT; i++) {
        size_t short_len = (size_t) (CANONICAL_MACS[i].min_key_bytes - 1);
        uint8_t *short_key = (uint8_t *) malloc(short_len == 0 ? 1 : short_len);
        ck_assert_ptr_nonnull(short_key);
        memset(short_key, 0x11, short_len);
        itb_mac_t *m = NULL;
        itb_status_t rc = itb_mac_new(CANONICAL_MACS[i].name,
                                      short_key, short_len, &m);
        ck_assert_int_eq(rc, ITB_BAD_INPUT);
        ck_assert_ptr_null(m);
        free(short_key);
    }
}
END_TEST

START_TEST(test_auth_roundtrip_all_macs_all_widths)
{
    size_t pt_len = 4096;
    uint8_t *plaintext = pseudo_plaintext(pt_len);

    for (size_t mi = 0; mi < CANONICAL_MACS_COUNT; mi++) {
        const char *mac_name = CANONICAL_MACS[mi].name;
        for (size_t hi = 0; hi < HASH_BY_WIDTH_COUNT; hi++) {
            const char *hash_name = HASH_BY_WIDTH[hi].name;

            itb_mac_t *mac = NULL;
            ck_assert_int_eq(itb_mac_new(mac_name, KEY_BYTES, sizeof(KEY_BYTES), &mac), ITB_OK);

            itb_seed_t *ns = NULL, *ds = NULL, *ss = NULL;
            ck_assert_int_eq(itb_seed_new(hash_name, 1024, &ns), ITB_OK);
            ck_assert_int_eq(itb_seed_new(hash_name, 1024, &ds), ITB_OK);
            ck_assert_int_eq(itb_seed_new(hash_name, 1024, &ss), ITB_OK);

            uint8_t *ct = NULL; size_t ct_len = 0;
            ck_assert_int_eq(itb_encrypt_auth(ns, ds, ss, mac,
                                              plaintext, pt_len, &ct, &ct_len), ITB_OK);
            uint8_t *pt = NULL; size_t pt_out_len = 0;
            ck_assert_int_eq(itb_decrypt_auth(ns, ds, ss, mac,
                                              ct, ct_len, &pt, &pt_out_len), ITB_OK);
            ck_assert_uint_eq(pt_out_len, pt_len);
            ck_assert_mem_eq(pt, plaintext, pt_len);

            /* Tamper at the dynamic header offset. */
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
}
END_TEST

START_TEST(test_auth_triple_roundtrip_all_macs_all_widths)
{
    size_t pt_len = 4096;
    uint8_t *plaintext = pseudo_plaintext(pt_len);

    for (size_t mi = 0; mi < CANONICAL_MACS_COUNT; mi++) {
        const char *mac_name = CANONICAL_MACS[mi].name;
        for (size_t hi = 0; hi < HASH_BY_WIDTH_COUNT; hi++) {
            const char *hash_name = HASH_BY_WIDTH[hi].name;

            itb_mac_t *mac = NULL;
            ck_assert_int_eq(itb_mac_new(mac_name, KEY_BYTES, sizeof(KEY_BYTES), &mac), ITB_OK);

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
}
END_TEST

START_TEST(test_auth_cross_mac_different_primitive)
{
    itb_seed_t *ns = NULL, *ds = NULL, *ss = NULL;
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &ns), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &ds), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &ss), ITB_OK);

    itb_mac_t *enc_mac = NULL, *dec_mac = NULL;
    ck_assert_int_eq(itb_mac_new("kmac256", KEY_BYTES, sizeof(KEY_BYTES), &enc_mac), ITB_OK);
    ck_assert_int_eq(itb_mac_new("hmac-sha256", KEY_BYTES, sizeof(KEY_BYTES), &dec_mac), ITB_OK);

    static const uint8_t plaintext[] = "authenticated payload";
    size_t pt_len = sizeof(plaintext) - 1;
    uint8_t *ct = NULL; size_t ct_len = 0;
    ck_assert_int_eq(itb_encrypt_auth(ns, ds, ss, enc_mac,
                                      plaintext, pt_len, &ct, &ct_len), ITB_OK);
    uint8_t *bad = NULL; size_t bad_len = 0;
    ck_assert_int_eq(itb_decrypt_auth(ns, ds, ss, dec_mac,
                                      ct, ct_len, &bad, &bad_len),
                     ITB_MAC_FAILURE);
    ck_assert_ptr_null(bad);

    itb_buffer_free(ct);
    itb_seed_free(ns);
    itb_seed_free(ds);
    itb_seed_free(ss);
    itb_mac_free(enc_mac);
    itb_mac_free(dec_mac);
}
END_TEST

START_TEST(test_auth_cross_mac_same_primitive_different_key)
{
    itb_seed_t *ns = NULL, *ds = NULL, *ss = NULL;
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &ns), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &ds), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &ss), ITB_OK);

    uint8_t key_a[32], key_b[32];
    memset(key_a, 0x01, sizeof(key_a));
    memset(key_b, 0x02, sizeof(key_b));

    itb_mac_t *enc_mac = NULL, *dec_mac = NULL;
    ck_assert_int_eq(itb_mac_new("hmac-sha256", key_a, sizeof(key_a), &enc_mac), ITB_OK);
    ck_assert_int_eq(itb_mac_new("hmac-sha256", key_b, sizeof(key_b), &dec_mac), ITB_OK);

    static const uint8_t plaintext[] = "authenticated payload";
    size_t pt_len = sizeof(plaintext) - 1;
    uint8_t *ct = NULL; size_t ct_len = 0;
    ck_assert_int_eq(itb_encrypt_auth(ns, ds, ss, enc_mac,
                                      plaintext, pt_len, &ct, &ct_len), ITB_OK);
    uint8_t *bad = NULL; size_t bad_len = 0;
    ck_assert_int_eq(itb_decrypt_auth(ns, ds, ss, dec_mac,
                                      ct, ct_len, &bad, &bad_len),
                     ITB_MAC_FAILURE);
    ck_assert_ptr_null(bad);

    itb_buffer_free(ct);
    itb_seed_free(ns);
    itb_seed_free(ds);
    itb_seed_free(ss);
    itb_mac_free(enc_mac);
    itb_mac_free(dec_mac);
}
END_TEST

int main(void)
{
    Suite *s = suite_create("auth");
    TCase *tc = tcase_create("core");
    tcase_set_timeout(tc, 60);
    tcase_add_test(tc, test_auth_list_macs);
    tcase_add_test(tc, test_auth_create_and_free);
    tcase_add_test(tc, test_auth_mac_free_release);
    tcase_add_test(tc, test_auth_bad_name);
    tcase_add_test(tc, test_auth_short_key);
    tcase_add_test(tc, test_auth_roundtrip_all_macs_all_widths);
    tcase_add_test(tc, test_auth_triple_roundtrip_all_macs_all_widths);
    tcase_add_test(tc, test_auth_cross_mac_different_primitive);
    tcase_add_test(tc, test_auth_cross_mac_same_primitive_different_key);
    suite_add_tcase(s, tc);

    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int failures = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failures == 0 ? 0 : 1;
}
