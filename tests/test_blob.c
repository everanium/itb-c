/*
 * test_blob.c — Blob128 / Blob256 / Blob512 export / import coverage.
 *
 * Mirrors bindings/rust/tests/test_blob.rs one-to-one. Confirms the
 * native Blob containers round-trip Single + Triple Ouroboros material
 * (with and without dedicated lockSeed, with and without MAC) and
 * preserve the captured globals across export / import.
 *
 * Per-binary fork() isolation gives this test its own libitb global
 * state, so no in-process serial lock is required.
 *
 * Note on the C surface. The string-resolver helper `itb::slot_from_name`
 * (a Rust-side wrapper convenience) is not part of the C public API —
 * the C binding exposes only the integer slot constants
 * (ITB_BLOB_SLOT_*). The corresponding Rust tests
 * (`blob_slot_from_name_round_trip`, `test_string_and_int_slots_equivalent`,
 * `test_invalid_slot_name`) therefore have no C analogue.
 */

#include <check.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "itb.h"

/* ------------------------------------------------------------------ */
/* Globals snapshot helpers                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    int nonce;
    int barrier;
    int bs;
    int ls;
} globals_t;

static void capture_globals(globals_t *g)
{
    g->nonce   = itb_get_nonce_bits();
    g->barrier = itb_get_barrier_fill();
    g->bs      = itb_get_bit_soup();
    g->ls      = itb_get_lock_soup();
}

static void restore_globals(const globals_t *g)
{
    (void) itb_set_nonce_bits(g->nonce);
    (void) itb_set_barrier_fill(g->barrier);
    (void) itb_set_bit_soup(g->bs);
    (void) itb_set_lock_soup(g->ls);
}

static void with_globals_begin(globals_t *prev)
{
    capture_globals(prev);
    ck_assert_int_eq(itb_set_nonce_bits(512), ITB_OK);
    ck_assert_int_eq(itb_set_barrier_fill(4), ITB_OK);
    ck_assert_int_eq(itb_set_bit_soup(1), ITB_OK);
    ck_assert_int_eq(itb_set_lock_soup(1), ITB_OK);
}

static void reset_globals(void)
{
    ck_assert_int_eq(itb_set_nonce_bits(128), ITB_OK);
    ck_assert_int_eq(itb_set_barrier_fill(1), ITB_OK);
    ck_assert_int_eq(itb_set_bit_soup(0), ITB_OK);
    ck_assert_int_eq(itb_set_lock_soup(0), ITB_OK);
}

static void assert_globals_restored(int nonce, int barrier, int bs, int ls)
{
    ck_assert_int_eq(itb_get_nonce_bits(),   nonce);
    ck_assert_int_eq(itb_get_barrier_fill(), barrier);
    ck_assert_int_eq(itb_get_bit_soup(),     bs);
    ck_assert_int_eq(itb_get_lock_soup(),    ls);
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

START_TEST(test_blob_blob256_single_export_import_roundtrip)
{
    /* Sender: stage hash keys + components into a fresh Blob256. */
    itb_blob256_t *sender = NULL;
    ck_assert_int_eq(itb_blob256_new(&sender), ITB_OK);

    uint8_t key_n[32], key_d[32], key_s[32], mac_key[32];
    for (uint8_t i = 0; i < 32; i++) {
        key_n[i]   = (uint8_t) (0xa0 ^ i);
        key_d[i]   = (uint8_t) (0xb0 ^ i);
        key_s[i]   = (uint8_t) (0xc0 ^ i);
        mac_key[i] = (uint8_t) (0xd0 ^ i);
    }
    uint64_t comps_n[16], comps_d[16], comps_s[16];
    for (uint64_t i = 0; i < 16; i++) {
        comps_n[i] = 0x1000 + i;
        comps_d[i] = 0x2000 + i;
        comps_s[i] = 0x3000 + i;
    }

    ck_assert_int_eq(itb_blob256_set_key(sender, ITB_BLOB_SLOT_N,
                                         key_n, sizeof(key_n)), ITB_OK);
    ck_assert_int_eq(itb_blob256_set_components(sender, ITB_BLOB_SLOT_N,
                                                comps_n, 16), ITB_OK);
    ck_assert_int_eq(itb_blob256_set_key(sender, ITB_BLOB_SLOT_D,
                                         key_d, sizeof(key_d)), ITB_OK);
    ck_assert_int_eq(itb_blob256_set_components(sender, ITB_BLOB_SLOT_D,
                                                comps_d, 16), ITB_OK);
    ck_assert_int_eq(itb_blob256_set_key(sender, ITB_BLOB_SLOT_S,
                                         key_s, sizeof(key_s)), ITB_OK);
    ck_assert_int_eq(itb_blob256_set_components(sender, ITB_BLOB_SLOT_S,
                                                comps_s, 16), ITB_OK);
    ck_assert_int_eq(itb_blob256_set_mac_key(sender, mac_key, sizeof(mac_key)), ITB_OK);
    ck_assert_int_eq(itb_blob256_set_mac_name(sender, "kmac256"), ITB_OK);

    uint8_t *blob_bytes = NULL; size_t blob_len = 0;
    ck_assert_int_eq(itb_blob256_export(sender, ITB_BLOB_OPT_MAC,
                                        &blob_bytes, &blob_len), ITB_OK);
    ck_assert_uint_gt(blob_len, 0);

    /* Receiver: a fresh Blob256 imports the bytes. */
    itb_blob256_t *receiver = NULL;
    ck_assert_int_eq(itb_blob256_new(&receiver), ITB_OK);
    ck_assert_int_eq(itb_blob256_import(receiver, blob_bytes, blob_len), ITB_OK);

    int width = 0, mode = 0;
    ck_assert_int_eq(itb_blob256_width(receiver, &width), ITB_OK);
    ck_assert_int_eq(width, 256);
    ck_assert_int_eq(itb_blob256_mode(receiver, &mode), ITB_OK);
    ck_assert_int_eq(mode, 1);

    uint8_t got_key[32]; size_t got_kl = 0;
    ck_assert_int_eq(itb_blob256_get_key(receiver, ITB_BLOB_SLOT_N,
                                         got_key, sizeof(got_key), &got_kl), ITB_OK);
    ck_assert_uint_eq(got_kl, 32);
    ck_assert_mem_eq(got_key, key_n, 32);
    ck_assert_int_eq(itb_blob256_get_key(receiver, ITB_BLOB_SLOT_D,
                                         got_key, sizeof(got_key), &got_kl), ITB_OK);
    ck_assert_mem_eq(got_key, key_d, 32);
    ck_assert_int_eq(itb_blob256_get_key(receiver, ITB_BLOB_SLOT_S,
                                         got_key, sizeof(got_key), &got_kl), ITB_OK);
    ck_assert_mem_eq(got_key, key_s, 32);

    uint64_t got_comps[16]; size_t got_cn = 0;
    ck_assert_int_eq(itb_blob256_get_components(receiver, ITB_BLOB_SLOT_N,
                                                got_comps, 16, &got_cn), ITB_OK);
    ck_assert_uint_eq(got_cn, 16);
    ck_assert_mem_eq(got_comps, comps_n, 16 * sizeof(uint64_t));
    ck_assert_int_eq(itb_blob256_get_components(receiver, ITB_BLOB_SLOT_D,
                                                got_comps, 16, &got_cn), ITB_OK);
    ck_assert_mem_eq(got_comps, comps_d, 16 * sizeof(uint64_t));
    ck_assert_int_eq(itb_blob256_get_components(receiver, ITB_BLOB_SLOT_S,
                                                got_comps, 16, &got_cn), ITB_OK);
    ck_assert_mem_eq(got_comps, comps_s, 16 * sizeof(uint64_t));

    uint8_t got_mac_key[32]; size_t got_mkl = 0;
    ck_assert_int_eq(itb_blob256_get_mac_key(receiver, got_mac_key,
                                             sizeof(got_mac_key), &got_mkl), ITB_OK);
    ck_assert_uint_eq(got_mkl, 32);
    ck_assert_mem_eq(got_mac_key, mac_key, 32);

    char got_mac_name[64]; size_t got_mnl = 0;
    ck_assert_int_eq(itb_blob256_get_mac_name(receiver, got_mac_name,
                                              sizeof(got_mac_name), &got_mnl), ITB_OK);
    ck_assert_str_eq(got_mac_name, "kmac256");

    itb_buffer_free(blob_bytes);
    itb_blob256_free(sender);
    itb_blob256_free(receiver);
}
END_TEST

START_TEST(test_blob_blob256_freshly_constructed_has_unset_mode)
{
    itb_blob256_t *b = NULL;
    ck_assert_int_eq(itb_blob256_new(&b), ITB_OK);
    int width = 0, mode = 0;
    ck_assert_int_eq(itb_blob256_width(b, &width), ITB_OK);
    ck_assert_int_eq(width, 256);
    ck_assert_int_eq(itb_blob256_mode(b, &mode), ITB_OK);
    ck_assert_int_eq(mode, 0);
    itb_blob256_free(b);
}
END_TEST

START_TEST(test_blob_drop_does_not_panic)
{
    for (int i = 0; i < 16; i++) {
        itb_blob256_t *b = NULL;
        ck_assert_int_eq(itb_blob256_new(&b), ITB_OK);
        itb_blob256_free(b);
    }
    /* Idempotent NULL-free contract. */
    itb_blob128_free(NULL);
    itb_blob256_free(NULL);
    itb_blob512_free(NULL);
}
END_TEST

START_TEST(test_blob_construct_each_width)
{
    itb_blob128_t *b1 = NULL;
    ck_assert_int_eq(itb_blob128_new(&b1), ITB_OK);
    int width = 0, mode = 0;
    ck_assert_int_eq(itb_blob128_width(b1, &width), ITB_OK);
    ck_assert_int_eq(width, 128);
    ck_assert_int_eq(itb_blob128_mode(b1, &mode), ITB_OK);
    ck_assert_int_eq(mode, 0);
    itb_blob128_free(b1);

    itb_blob256_t *b2 = NULL;
    ck_assert_int_eq(itb_blob256_new(&b2), ITB_OK);
    ck_assert_int_eq(itb_blob256_width(b2, &width), ITB_OK);
    ck_assert_int_eq(width, 256);
    ck_assert_int_eq(itb_blob256_mode(b2, &mode), ITB_OK);
    ck_assert_int_eq(mode, 0);
    itb_blob256_free(b2);

    itb_blob512_t *b3 = NULL;
    ck_assert_int_eq(itb_blob512_new(&b3), ITB_OK);
    ck_assert_int_eq(itb_blob512_width(b3, &width), ITB_OK);
    ck_assert_int_eq(width, 512);
    ck_assert_int_eq(itb_blob512_mode(b3, &mode), ITB_OK);
    ck_assert_int_eq(mode, 0);
    itb_blob512_free(b3);
}
END_TEST

/* ------------------------------------------------------------------ */
/* Helpers for the full-matrix Single / Triple Blob512 round-trips     */
/* ------------------------------------------------------------------ */

static void blob512_single_one(const uint8_t *plaintext, size_t pt_len,
                               int with_ls, int with_mac)
{
    const char *primitive = "areion512";
    int key_bits = 2048;

    itb_seed_t *ns = NULL, *ds = NULL, *ss = NULL, *ls = NULL;
    ck_assert_int_eq(itb_seed_new(primitive, key_bits, &ns), ITB_OK);
    ck_assert_int_eq(itb_seed_new(primitive, key_bits, &ds), ITB_OK);
    ck_assert_int_eq(itb_seed_new(primitive, key_bits, &ss), ITB_OK);
    if (with_ls) {
        ck_assert_int_eq(itb_seed_new(primitive, key_bits, &ls), ITB_OK);
        ck_assert_int_eq(itb_seed_attach_lock_seed(ns, ls), ITB_OK);
    }

    uint8_t mac_key[32];
    for (uint8_t i = 0; i < 32; i++) mac_key[i] = (uint8_t) (0x55 ^ i);
    itb_mac_t *mac = NULL;
    if (with_mac) {
        ck_assert_int_eq(itb_mac_new("kmac256", mac_key, sizeof(mac_key), &mac), ITB_OK);
    }

    uint8_t *ct = NULL; size_t ct_len = 0;
    if (with_mac) {
        ck_assert_int_eq(itb_encrypt_auth(ns, ds, ss, mac,
                                          plaintext, pt_len, &ct, &ct_len), ITB_OK);
    } else {
        ck_assert_int_eq(itb_encrypt(ns, ds, ss,
                                     plaintext, pt_len, &ct, &ct_len), ITB_OK);
    }

    itb_blob512_t *src = NULL;
    ck_assert_int_eq(itb_blob512_new(&src), ITB_OK);

    uint8_t hk[64]; size_t hk_len = 0;
    uint64_t comps[32]; size_t cn = 0;

    itb_seed_t *seeds_for_blob[3] = {ns, ds, ss};
    int slots_for_blob[3] = {ITB_BLOB_SLOT_N, ITB_BLOB_SLOT_D, ITB_BLOB_SLOT_S};
    for (int i = 0; i < 3; i++) {
        ck_assert_int_eq(itb_seed_hash_key(seeds_for_blob[i], hk, sizeof(hk), &hk_len), ITB_OK);
        ck_assert_int_eq(itb_blob512_set_key(src, slots_for_blob[i], hk, hk_len), ITB_OK);
        ck_assert_int_eq(itb_seed_components(seeds_for_blob[i], comps, 32, &cn), ITB_OK);
        ck_assert_int_eq(itb_blob512_set_components(src, slots_for_blob[i], comps, cn), ITB_OK);
    }
    if (with_ls) {
        ck_assert_int_eq(itb_seed_hash_key(ls, hk, sizeof(hk), &hk_len), ITB_OK);
        ck_assert_int_eq(itb_blob512_set_key(src, ITB_BLOB_SLOT_L, hk, hk_len), ITB_OK);
        ck_assert_int_eq(itb_seed_components(ls, comps, 32, &cn), ITB_OK);
        ck_assert_int_eq(itb_blob512_set_components(src, ITB_BLOB_SLOT_L, comps, cn), ITB_OK);
    }
    if (with_mac) {
        ck_assert_int_eq(itb_blob512_set_mac_key(src, mac_key, sizeof(mac_key)), ITB_OK);
        ck_assert_int_eq(itb_blob512_set_mac_name(src, "kmac256"), ITB_OK);
    }

    int opts = (with_ls ? ITB_BLOB_OPT_LOCKSEED : 0) | (with_mac ? ITB_BLOB_OPT_MAC : 0);
    uint8_t *blob = NULL; size_t blob_len = 0;
    ck_assert_int_eq(itb_blob512_export(src, opts, &blob, &blob_len), ITB_OK);

    reset_globals();
    itb_blob512_t *dst = NULL;
    ck_assert_int_eq(itb_blob512_new(&dst), ITB_OK);
    ck_assert_int_eq(itb_blob512_import(dst, blob, blob_len), ITB_OK);
    int dst_mode = 0;
    ck_assert_int_eq(itb_blob512_mode(dst, &dst_mode), ITB_OK);
    ck_assert_int_eq(dst_mode, 1);
    assert_globals_restored(512, 4, 1, 1);

    /* Rebuild seeds from the imported blob. */
    itb_seed_t *ns2 = NULL, *ds2 = NULL, *ss2 = NULL, *ls2 = NULL;
    uint8_t hk2[64]; size_t hk2l = 0;
    uint64_t comps2[32]; size_t cn2 = 0;

    ck_assert_int_eq(itb_blob512_get_components(dst, ITB_BLOB_SLOT_N, comps2, 32, &cn2), ITB_OK);
    ck_assert_int_eq(itb_blob512_get_key(dst, ITB_BLOB_SLOT_N, hk2, sizeof(hk2), &hk2l), ITB_OK);
    ck_assert_int_eq(itb_seed_from_components(primitive, comps2, cn2, hk2, hk2l, &ns2), ITB_OK);

    ck_assert_int_eq(itb_blob512_get_components(dst, ITB_BLOB_SLOT_D, comps2, 32, &cn2), ITB_OK);
    ck_assert_int_eq(itb_blob512_get_key(dst, ITB_BLOB_SLOT_D, hk2, sizeof(hk2), &hk2l), ITB_OK);
    ck_assert_int_eq(itb_seed_from_components(primitive, comps2, cn2, hk2, hk2l, &ds2), ITB_OK);

    ck_assert_int_eq(itb_blob512_get_components(dst, ITB_BLOB_SLOT_S, comps2, 32, &cn2), ITB_OK);
    ck_assert_int_eq(itb_blob512_get_key(dst, ITB_BLOB_SLOT_S, hk2, sizeof(hk2), &hk2l), ITB_OK);
    ck_assert_int_eq(itb_seed_from_components(primitive, comps2, cn2, hk2, hk2l, &ss2), ITB_OK);

    if (with_ls) {
        ck_assert_int_eq(itb_blob512_get_components(dst, ITB_BLOB_SLOT_L, comps2, 32, &cn2), ITB_OK);
        ck_assert_int_eq(itb_blob512_get_key(dst, ITB_BLOB_SLOT_L, hk2, sizeof(hk2), &hk2l), ITB_OK);
        ck_assert_int_eq(itb_seed_from_components(primitive, comps2, cn2, hk2, hk2l, &ls2), ITB_OK);
        ck_assert_int_eq(itb_seed_attach_lock_seed(ns2, ls2), ITB_OK);
    }

    itb_mac_t *mac2 = NULL;
    if (with_mac) {
        char got_mn[64]; size_t got_mnl = 0;
        ck_assert_int_eq(itb_blob512_get_mac_name(dst, got_mn, sizeof(got_mn), &got_mnl), ITB_OK);
        ck_assert_str_eq(got_mn, "kmac256");
        uint8_t got_mk[32]; size_t got_mkl = 0;
        ck_assert_int_eq(itb_blob512_get_mac_key(dst, got_mk, sizeof(got_mk), &got_mkl), ITB_OK);
        ck_assert_uint_eq(got_mkl, 32);
        ck_assert_mem_eq(got_mk, mac_key, 32);
        ck_assert_int_eq(itb_mac_new("kmac256", got_mk, got_mkl, &mac2), ITB_OK);
    }

    uint8_t *pt = NULL; size_t pt_out_len = 0;
    if (with_mac) {
        ck_assert_int_eq(itb_decrypt_auth(ns2, ds2, ss2, mac2,
                                          ct, ct_len, &pt, &pt_out_len), ITB_OK);
    } else {
        ck_assert_int_eq(itb_decrypt(ns2, ds2, ss2,
                                     ct, ct_len, &pt, &pt_out_len), ITB_OK);
    }
    ck_assert_uint_eq(pt_out_len, pt_len);
    ck_assert_mem_eq(pt, plaintext, pt_out_len);

    itb_buffer_free(blob);
    itb_buffer_free(ct);
    itb_buffer_free(pt);
    itb_blob512_free(src);
    itb_blob512_free(dst);
    itb_seed_free(ns2);
    itb_seed_free(ds2);
    itb_seed_free(ss2);
    if (ls2 != NULL) itb_seed_free(ls2);
    if (mac2 != NULL) itb_mac_free(mac2);

    itb_seed_free(ns);
    itb_seed_free(ds);
    itb_seed_free(ss);
    if (ls != NULL) itb_seed_free(ls);
    if (mac != NULL) itb_mac_free(mac);
}

START_TEST(test_blob_blob512_single_full_matrix)
{
    static const uint8_t plaintext[] = "rs blob512 single round-trip payload";
    size_t pt_len = sizeof(plaintext) - 1;
    for (int with_ls = 0; with_ls <= 1; with_ls++) {
        for (int with_mac = 0; with_mac <= 1; with_mac++) {
            globals_t prev;
            with_globals_begin(&prev);
            blob512_single_one(plaintext, pt_len, with_ls, with_mac);
            restore_globals(&prev);
        }
    }
}
END_TEST

static void blob512_triple_one(const uint8_t *plaintext, size_t pt_len,
                               int with_ls, int with_mac)
{
    const char *primitive = "areion512";
    int key_bits = 2048;

    itb_seed_t *seeds[7] = {NULL};
    for (int k = 0; k < 7; k++) {
        ck_assert_int_eq(itb_seed_new(primitive, key_bits, &seeds[k]), ITB_OK);
    }
    itb_seed_t *ls = NULL;
    if (with_ls) {
        ck_assert_int_eq(itb_seed_new(primitive, key_bits, &ls), ITB_OK);
        ck_assert_int_eq(itb_seed_attach_lock_seed(seeds[0], ls), ITB_OK);
    }

    uint8_t mac_key[32];
    for (uint8_t i = 0; i < 32; i++) mac_key[i] = (uint8_t) (0x37 ^ i);
    itb_mac_t *mac = NULL;
    if (with_mac) {
        ck_assert_int_eq(itb_mac_new("kmac256", mac_key, sizeof(mac_key), &mac), ITB_OK);
    }

    uint8_t *ct = NULL; size_t ct_len = 0;
    if (with_mac) {
        ck_assert_int_eq(itb_encrypt_auth_triple(seeds[0], seeds[1], seeds[2], seeds[3],
                                                 seeds[4], seeds[5], seeds[6], mac,
                                                 plaintext, pt_len, &ct, &ct_len), ITB_OK);
    } else {
        ck_assert_int_eq(itb_encrypt_triple(seeds[0], seeds[1], seeds[2], seeds[3],
                                            seeds[4], seeds[5], seeds[6],
                                            plaintext, pt_len, &ct, &ct_len), ITB_OK);
    }

    itb_blob512_t *src = NULL;
    ck_assert_int_eq(itb_blob512_new(&src), ITB_OK);

    int triple_slots[7] = {
        ITB_BLOB_SLOT_N,
        ITB_BLOB_SLOT_D1, ITB_BLOB_SLOT_D2, ITB_BLOB_SLOT_D3,
        ITB_BLOB_SLOT_S1, ITB_BLOB_SLOT_S2, ITB_BLOB_SLOT_S3,
    };
    uint8_t hk[64]; size_t hk_len = 0;
    uint64_t comps[32]; size_t cn = 0;
    for (int k = 0; k < 7; k++) {
        ck_assert_int_eq(itb_seed_hash_key(seeds[k], hk, sizeof(hk), &hk_len), ITB_OK);
        ck_assert_int_eq(itb_blob512_set_key(src, triple_slots[k], hk, hk_len), ITB_OK);
        ck_assert_int_eq(itb_seed_components(seeds[k], comps, 32, &cn), ITB_OK);
        ck_assert_int_eq(itb_blob512_set_components(src, triple_slots[k], comps, cn), ITB_OK);
    }
    if (with_ls) {
        ck_assert_int_eq(itb_seed_hash_key(ls, hk, sizeof(hk), &hk_len), ITB_OK);
        ck_assert_int_eq(itb_blob512_set_key(src, ITB_BLOB_SLOT_L, hk, hk_len), ITB_OK);
        ck_assert_int_eq(itb_seed_components(ls, comps, 32, &cn), ITB_OK);
        ck_assert_int_eq(itb_blob512_set_components(src, ITB_BLOB_SLOT_L, comps, cn), ITB_OK);
    }
    if (with_mac) {
        ck_assert_int_eq(itb_blob512_set_mac_key(src, mac_key, sizeof(mac_key)), ITB_OK);
        ck_assert_int_eq(itb_blob512_set_mac_name(src, "kmac256"), ITB_OK);
    }

    int opts = (with_ls ? ITB_BLOB_OPT_LOCKSEED : 0) | (with_mac ? ITB_BLOB_OPT_MAC : 0);
    uint8_t *blob = NULL; size_t blob_len = 0;
    ck_assert_int_eq(itb_blob512_export3(src, opts, &blob, &blob_len), ITB_OK);

    reset_globals();
    itb_blob512_t *dst = NULL;
    ck_assert_int_eq(itb_blob512_new(&dst), ITB_OK);
    ck_assert_int_eq(itb_blob512_import3(dst, blob, blob_len), ITB_OK);
    int dst_mode = 0;
    ck_assert_int_eq(itb_blob512_mode(dst, &dst_mode), ITB_OK);
    ck_assert_int_eq(dst_mode, 3);
    assert_globals_restored(512, 4, 1, 1);

    itb_seed_t *seeds2[7] = {NULL};
    uint8_t hk2[64]; size_t hk2l = 0;
    uint64_t comps2[32]; size_t cn2 = 0;
    for (int k = 0; k < 7; k++) {
        ck_assert_int_eq(itb_blob512_get_components(dst, triple_slots[k],
                                                    comps2, 32, &cn2), ITB_OK);
        ck_assert_int_eq(itb_blob512_get_key(dst, triple_slots[k],
                                             hk2, sizeof(hk2), &hk2l), ITB_OK);
        ck_assert_int_eq(itb_seed_from_components(primitive, comps2, cn2,
                                                  hk2, hk2l, &seeds2[k]), ITB_OK);
    }
    itb_seed_t *ls2 = NULL;
    if (with_ls) {
        ck_assert_int_eq(itb_blob512_get_components(dst, ITB_BLOB_SLOT_L,
                                                    comps2, 32, &cn2), ITB_OK);
        ck_assert_int_eq(itb_blob512_get_key(dst, ITB_BLOB_SLOT_L,
                                             hk2, sizeof(hk2), &hk2l), ITB_OK);
        ck_assert_int_eq(itb_seed_from_components(primitive, comps2, cn2,
                                                  hk2, hk2l, &ls2), ITB_OK);
        ck_assert_int_eq(itb_seed_attach_lock_seed(seeds2[0], ls2), ITB_OK);
    }

    itb_mac_t *mac2 = NULL;
    if (with_mac) {
        uint8_t got_mk[32]; size_t got_mkl = 0;
        ck_assert_int_eq(itb_blob512_get_mac_key(dst, got_mk, sizeof(got_mk), &got_mkl), ITB_OK);
        ck_assert_int_eq(itb_mac_new("kmac256", got_mk, got_mkl, &mac2), ITB_OK);
    }

    uint8_t *pt = NULL; size_t pt_out_len = 0;
    if (with_mac) {
        ck_assert_int_eq(itb_decrypt_auth_triple(seeds2[0], seeds2[1], seeds2[2], seeds2[3],
                                                 seeds2[4], seeds2[5], seeds2[6], mac2,
                                                 ct, ct_len, &pt, &pt_out_len), ITB_OK);
    } else {
        ck_assert_int_eq(itb_decrypt_triple(seeds2[0], seeds2[1], seeds2[2], seeds2[3],
                                            seeds2[4], seeds2[5], seeds2[6],
                                            ct, ct_len, &pt, &pt_out_len), ITB_OK);
    }
    ck_assert_uint_eq(pt_out_len, pt_len);
    ck_assert_mem_eq(pt, plaintext, pt_len);

    itb_buffer_free(blob);
    itb_buffer_free(ct);
    itb_buffer_free(pt);
    itb_blob512_free(src);
    itb_blob512_free(dst);
    for (int k = 0; k < 7; k++) {
        itb_seed_free(seeds[k]);
        itb_seed_free(seeds2[k]);
    }
    if (ls != NULL) itb_seed_free(ls);
    if (ls2 != NULL) itb_seed_free(ls2);
    if (mac != NULL) itb_mac_free(mac);
    if (mac2 != NULL) itb_mac_free(mac2);
}

START_TEST(test_blob_blob512_triple_full_matrix)
{
    static const uint8_t plaintext[] = "rs blob512 triple round-trip payload";
    size_t pt_len = sizeof(plaintext) - 1;
    for (int with_ls = 0; with_ls <= 1; with_ls++) {
        for (int with_mac = 0; with_mac <= 1; with_mac++) {
            globals_t prev;
            with_globals_begin(&prev);
            blob512_triple_one(plaintext, pt_len, with_ls, with_mac);
            restore_globals(&prev);
        }
    }
}
END_TEST

START_TEST(test_blob_blob256_single)
{
    globals_t prev;
    with_globals_begin(&prev);

    static const uint8_t plaintext[] = "rs blob256 single round-trip";
    size_t pt_len = sizeof(plaintext) - 1;

    itb_seed_t *ns = NULL, *ds = NULL, *ss = NULL;
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &ns), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &ds), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &ss), ITB_OK);
    uint8_t *ct = NULL; size_t ct_len = 0;
    ck_assert_int_eq(itb_encrypt(ns, ds, ss, plaintext, pt_len, &ct, &ct_len), ITB_OK);

    itb_blob256_t *src = NULL;
    ck_assert_int_eq(itb_blob256_new(&src), ITB_OK);
    itb_seed_t *seeds_for_blob[3] = {ns, ds, ss};
    int slots_for_blob[3] = {ITB_BLOB_SLOT_N, ITB_BLOB_SLOT_D, ITB_BLOB_SLOT_S};
    for (int i = 0; i < 3; i++) {
        uint8_t hk[64]; size_t hkl = 0;
        ck_assert_int_eq(itb_seed_hash_key(seeds_for_blob[i], hk, sizeof(hk), &hkl), ITB_OK);
        ck_assert_int_eq(itb_blob256_set_key(src, slots_for_blob[i], hk, hkl), ITB_OK);
        uint64_t comps[32]; size_t cn = 0;
        ck_assert_int_eq(itb_seed_components(seeds_for_blob[i], comps, 32, &cn), ITB_OK);
        ck_assert_int_eq(itb_blob256_set_components(src, slots_for_blob[i], comps, cn), ITB_OK);
    }
    uint8_t *blob = NULL; size_t blob_len = 0;
    ck_assert_int_eq(itb_blob256_export(src, 0, &blob, &blob_len), ITB_OK);

    reset_globals();
    itb_blob256_t *dst = NULL;
    ck_assert_int_eq(itb_blob256_new(&dst), ITB_OK);
    ck_assert_int_eq(itb_blob256_import(dst, blob, blob_len), ITB_OK);
    int dst_mode = 0;
    ck_assert_int_eq(itb_blob256_mode(dst, &dst_mode), ITB_OK);
    ck_assert_int_eq(dst_mode, 1);

    itb_seed_t *ns2 = NULL, *ds2 = NULL, *ss2 = NULL;
    itb_seed_t **out2[3] = {&ns2, &ds2, &ss2};
    for (int i = 0; i < 3; i++) {
        uint8_t hk2[64]; size_t hk2l = 0;
        uint64_t comps2[32]; size_t cn2 = 0;
        ck_assert_int_eq(itb_blob256_get_components(dst, slots_for_blob[i], comps2, 32, &cn2), ITB_OK);
        ck_assert_int_eq(itb_blob256_get_key(dst, slots_for_blob[i], hk2, sizeof(hk2), &hk2l), ITB_OK);
        ck_assert_int_eq(itb_seed_from_components("blake3", comps2, cn2, hk2, hk2l, out2[i]), ITB_OK);
    }
    uint8_t *pt = NULL; size_t pt_out_len = 0;
    ck_assert_int_eq(itb_decrypt(ns2, ds2, ss2, ct, ct_len, &pt, &pt_out_len), ITB_OK);
    ck_assert_uint_eq(pt_out_len, pt_len);
    ck_assert_mem_eq(pt, plaintext, pt_len);

    itb_buffer_free(blob);
    itb_buffer_free(ct);
    itb_buffer_free(pt);
    itb_blob256_free(src);
    itb_blob256_free(dst);
    itb_seed_free(ns); itb_seed_free(ds); itb_seed_free(ss);
    itb_seed_free(ns2); itb_seed_free(ds2); itb_seed_free(ss2);

    restore_globals(&prev);
}
END_TEST

START_TEST(test_blob_blob256_triple)
{
    globals_t prev;
    with_globals_begin(&prev);

    static const uint8_t plaintext[] = "rs blob256 triple round-trip";
    size_t pt_len = sizeof(plaintext) - 1;

    itb_seed_t *seeds[7] = {NULL};
    for (int k = 0; k < 7; k++) {
        ck_assert_int_eq(itb_seed_new("blake3", 1024, &seeds[k]), ITB_OK);
    }
    uint8_t *ct = NULL; size_t ct_len = 0;
    ck_assert_int_eq(itb_encrypt_triple(seeds[0], seeds[1], seeds[2], seeds[3],
                                        seeds[4], seeds[5], seeds[6],
                                        plaintext, pt_len, &ct, &ct_len), ITB_OK);

    int triple_slots[7] = {
        ITB_BLOB_SLOT_N,
        ITB_BLOB_SLOT_D1, ITB_BLOB_SLOT_D2, ITB_BLOB_SLOT_D3,
        ITB_BLOB_SLOT_S1, ITB_BLOB_SLOT_S2, ITB_BLOB_SLOT_S3,
    };
    itb_blob256_t *src = NULL;
    ck_assert_int_eq(itb_blob256_new(&src), ITB_OK);
    for (int k = 0; k < 7; k++) {
        uint8_t hk[64]; size_t hkl = 0;
        ck_assert_int_eq(itb_seed_hash_key(seeds[k], hk, sizeof(hk), &hkl), ITB_OK);
        ck_assert_int_eq(itb_blob256_set_key(src, triple_slots[k], hk, hkl), ITB_OK);
        uint64_t comps[32]; size_t cn = 0;
        ck_assert_int_eq(itb_seed_components(seeds[k], comps, 32, &cn), ITB_OK);
        ck_assert_int_eq(itb_blob256_set_components(src, triple_slots[k], comps, cn), ITB_OK);
    }
    uint8_t *blob = NULL; size_t blob_len = 0;
    ck_assert_int_eq(itb_blob256_export3(src, 0, &blob, &blob_len), ITB_OK);

    reset_globals();
    itb_blob256_t *dst = NULL;
    ck_assert_int_eq(itb_blob256_new(&dst), ITB_OK);
    ck_assert_int_eq(itb_blob256_import3(dst, blob, blob_len), ITB_OK);
    int dst_mode = 0;
    ck_assert_int_eq(itb_blob256_mode(dst, &dst_mode), ITB_OK);
    ck_assert_int_eq(dst_mode, 3);

    itb_seed_t *seeds2[7] = {NULL};
    for (int k = 0; k < 7; k++) {
        uint8_t hk2[64]; size_t hk2l = 0;
        uint64_t comps2[32]; size_t cn2 = 0;
        ck_assert_int_eq(itb_blob256_get_components(dst, triple_slots[k], comps2, 32, &cn2), ITB_OK);
        ck_assert_int_eq(itb_blob256_get_key(dst, triple_slots[k], hk2, sizeof(hk2), &hk2l), ITB_OK);
        ck_assert_int_eq(itb_seed_from_components("blake3", comps2, cn2, hk2, hk2l, &seeds2[k]), ITB_OK);
    }
    uint8_t *pt = NULL; size_t pt_out_len = 0;
    ck_assert_int_eq(itb_decrypt_triple(seeds2[0], seeds2[1], seeds2[2], seeds2[3],
                                        seeds2[4], seeds2[5], seeds2[6],
                                        ct, ct_len, &pt, &pt_out_len), ITB_OK);
    ck_assert_uint_eq(pt_out_len, pt_len);
    ck_assert_mem_eq(pt, plaintext, pt_len);

    itb_buffer_free(blob);
    itb_buffer_free(ct);
    itb_buffer_free(pt);
    itb_blob256_free(src);
    itb_blob256_free(dst);
    for (int k = 0; k < 7; k++) {
        itb_seed_free(seeds[k]);
        itb_seed_free(seeds2[k]);
    }

    restore_globals(&prev);
}
END_TEST

START_TEST(test_blob_blob128_siphash_single)
{
    globals_t prev;
    with_globals_begin(&prev);

    static const uint8_t plaintext[] = "rs blob128 siphash round-trip";
    size_t pt_len = sizeof(plaintext) - 1;

    itb_seed_t *ns = NULL, *ds = NULL, *ss = NULL;
    ck_assert_int_eq(itb_seed_new("siphash24", 512, &ns), ITB_OK);
    ck_assert_int_eq(itb_seed_new("siphash24", 512, &ds), ITB_OK);
    ck_assert_int_eq(itb_seed_new("siphash24", 512, &ss), ITB_OK);
    uint8_t *ct = NULL; size_t ct_len = 0;
    ck_assert_int_eq(itb_encrypt(ns, ds, ss, plaintext, pt_len, &ct, &ct_len), ITB_OK);

    itb_blob128_t *src = NULL;
    ck_assert_int_eq(itb_blob128_new(&src), ITB_OK);
    itb_seed_t *seeds_for_blob[3] = {ns, ds, ss};
    int slots_for_blob[3] = {ITB_BLOB_SLOT_N, ITB_BLOB_SLOT_D, ITB_BLOB_SLOT_S};
    for (int i = 0; i < 3; i++) {
        uint8_t hk[16]; size_t hkl = 0;
        ck_assert_int_eq(itb_seed_hash_key(seeds_for_blob[i], hk, sizeof(hk), &hkl), ITB_OK);
        ck_assert_uint_eq(hkl, 0); /* siphash24 carries no fixed key */
        ck_assert_int_eq(itb_blob128_set_key(src, slots_for_blob[i], hk, hkl), ITB_OK);
        uint64_t comps[32]; size_t cn = 0;
        ck_assert_int_eq(itb_seed_components(seeds_for_blob[i], comps, 32, &cn), ITB_OK);
        ck_assert_int_eq(itb_blob128_set_components(src, slots_for_blob[i], comps, cn), ITB_OK);
    }
    uint8_t *blob = NULL; size_t blob_len = 0;
    ck_assert_int_eq(itb_blob128_export(src, 0, &blob, &blob_len), ITB_OK);

    reset_globals();
    itb_blob128_t *dst = NULL;
    ck_assert_int_eq(itb_blob128_new(&dst), ITB_OK);
    ck_assert_int_eq(itb_blob128_import(dst, blob, blob_len), ITB_OK);

    itb_seed_t *ns2 = NULL, *ds2 = NULL, *ss2 = NULL;
    itb_seed_t **out2[3] = {&ns2, &ds2, &ss2};
    for (int i = 0; i < 3; i++) {
        uint64_t comps2[32]; size_t cn2 = 0;
        ck_assert_int_eq(itb_blob128_get_components(dst, slots_for_blob[i], comps2, 32, &cn2), ITB_OK);
        ck_assert_int_eq(itb_seed_from_components("siphash24", comps2, cn2,
                                                  NULL, 0, out2[i]), ITB_OK);
    }
    uint8_t *pt = NULL; size_t pt_out_len = 0;
    ck_assert_int_eq(itb_decrypt(ns2, ds2, ss2, ct, ct_len, &pt, &pt_out_len), ITB_OK);
    ck_assert_uint_eq(pt_out_len, pt_len);
    ck_assert_mem_eq(pt, plaintext, pt_len);

    itb_buffer_free(blob);
    itb_buffer_free(ct);
    itb_buffer_free(pt);
    itb_blob128_free(src);
    itb_blob128_free(dst);
    itb_seed_free(ns); itb_seed_free(ds); itb_seed_free(ss);
    itb_seed_free(ns2); itb_seed_free(ds2); itb_seed_free(ss2);

    restore_globals(&prev);
}
END_TEST

START_TEST(test_blob_blob128_aescmac_single)
{
    globals_t prev;
    with_globals_begin(&prev);

    static const uint8_t plaintext[] = "rs blob128 aescmac round-trip";
    size_t pt_len = sizeof(plaintext) - 1;

    itb_seed_t *ns = NULL, *ds = NULL, *ss = NULL;
    ck_assert_int_eq(itb_seed_new("aescmac", 512, &ns), ITB_OK);
    ck_assert_int_eq(itb_seed_new("aescmac", 512, &ds), ITB_OK);
    ck_assert_int_eq(itb_seed_new("aescmac", 512, &ss), ITB_OK);
    uint8_t *ct = NULL; size_t ct_len = 0;
    ck_assert_int_eq(itb_encrypt(ns, ds, ss, plaintext, pt_len, &ct, &ct_len), ITB_OK);

    itb_blob128_t *src = NULL;
    ck_assert_int_eq(itb_blob128_new(&src), ITB_OK);
    itb_seed_t *seeds_for_blob[3] = {ns, ds, ss};
    int slots_for_blob[3] = {ITB_BLOB_SLOT_N, ITB_BLOB_SLOT_D, ITB_BLOB_SLOT_S};
    for (int i = 0; i < 3; i++) {
        uint8_t hk[16]; size_t hkl = 0;
        ck_assert_int_eq(itb_seed_hash_key(seeds_for_blob[i], hk, sizeof(hk), &hkl), ITB_OK);
        ck_assert_uint_eq(hkl, 16); /* aescmac uses a 16-byte fixed key */
        ck_assert_int_eq(itb_blob128_set_key(src, slots_for_blob[i], hk, hkl), ITB_OK);
        uint64_t comps[32]; size_t cn = 0;
        ck_assert_int_eq(itb_seed_components(seeds_for_blob[i], comps, 32, &cn), ITB_OK);
        ck_assert_int_eq(itb_blob128_set_components(src, slots_for_blob[i], comps, cn), ITB_OK);
    }
    uint8_t *blob = NULL; size_t blob_len = 0;
    ck_assert_int_eq(itb_blob128_export(src, 0, &blob, &blob_len), ITB_OK);

    reset_globals();
    itb_blob128_t *dst = NULL;
    ck_assert_int_eq(itb_blob128_new(&dst), ITB_OK);
    ck_assert_int_eq(itb_blob128_import(dst, blob, blob_len), ITB_OK);

    itb_seed_t *ns2 = NULL, *ds2 = NULL, *ss2 = NULL;
    itb_seed_t **out2[3] = {&ns2, &ds2, &ss2};
    for (int i = 0; i < 3; i++) {
        uint8_t hk2[16]; size_t hk2l = 0;
        uint64_t comps2[32]; size_t cn2 = 0;
        ck_assert_int_eq(itb_blob128_get_components(dst, slots_for_blob[i], comps2, 32, &cn2), ITB_OK);
        ck_assert_int_eq(itb_blob128_get_key(dst, slots_for_blob[i], hk2, sizeof(hk2), &hk2l), ITB_OK);
        ck_assert_int_eq(itb_seed_from_components("aescmac", comps2, cn2,
                                                  hk2, hk2l, out2[i]), ITB_OK);
    }
    uint8_t *pt = NULL; size_t pt_out_len = 0;
    ck_assert_int_eq(itb_decrypt(ns2, ds2, ss2, ct, ct_len, &pt, &pt_out_len), ITB_OK);
    ck_assert_uint_eq(pt_out_len, pt_len);
    ck_assert_mem_eq(pt, plaintext, pt_len);

    itb_buffer_free(blob);
    itb_buffer_free(ct);
    itb_buffer_free(pt);
    itb_blob128_free(src);
    itb_blob128_free(dst);
    itb_seed_free(ns); itb_seed_free(ds); itb_seed_free(ss);
    itb_seed_free(ns2); itb_seed_free(ds2); itb_seed_free(ss2);

    restore_globals(&prev);
}
END_TEST

START_TEST(test_blob_mode_mismatch)
{
    globals_t prev;
    with_globals_begin(&prev);

    itb_seed_t *ns = NULL, *ds = NULL, *ss = NULL;
    ck_assert_int_eq(itb_seed_new("areion512", 1024, &ns), ITB_OK);
    ck_assert_int_eq(itb_seed_new("areion512", 1024, &ds), ITB_OK);
    ck_assert_int_eq(itb_seed_new("areion512", 1024, &ss), ITB_OK);

    itb_blob512_t *src = NULL;
    ck_assert_int_eq(itb_blob512_new(&src), ITB_OK);
    itb_seed_t *seeds_for_blob[3] = {ns, ds, ss};
    int slots_for_blob[3] = {ITB_BLOB_SLOT_N, ITB_BLOB_SLOT_D, ITB_BLOB_SLOT_S};
    for (int i = 0; i < 3; i++) {
        uint8_t hk[64]; size_t hkl = 0;
        ck_assert_int_eq(itb_seed_hash_key(seeds_for_blob[i], hk, sizeof(hk), &hkl), ITB_OK);
        ck_assert_int_eq(itb_blob512_set_key(src, slots_for_blob[i], hk, hkl), ITB_OK);
        uint64_t comps[32]; size_t cn = 0;
        ck_assert_int_eq(itb_seed_components(seeds_for_blob[i], comps, 32, &cn), ITB_OK);
        ck_assert_int_eq(itb_blob512_set_components(src, slots_for_blob[i], comps, cn), ITB_OK);
    }
    uint8_t *blob = NULL; size_t blob_len = 0;
    ck_assert_int_eq(itb_blob512_export(src, 0, &blob, &blob_len), ITB_OK);

    itb_blob512_t *dst = NULL;
    ck_assert_int_eq(itb_blob512_new(&dst), ITB_OK);
    /* Single-mode blob → import3 must reject. */
    ck_assert_int_eq(itb_blob512_import3(dst, blob, blob_len), ITB_BLOB_MODE_MISMATCH);

    itb_buffer_free(blob);
    itb_blob512_free(src);
    itb_blob512_free(dst);
    itb_seed_free(ns); itb_seed_free(ds); itb_seed_free(ss);

    restore_globals(&prev);
}
END_TEST

START_TEST(test_blob_malformed)
{
    itb_blob512_t *b = NULL;
    ck_assert_int_eq(itb_blob512_new(&b), ITB_OK);
    static const char garbage[] = "{not json";
    ck_assert_int_eq(itb_blob512_import(b, garbage, sizeof(garbage) - 1),
                     ITB_BLOB_MALFORMED);
    itb_blob512_free(b);
}
END_TEST

START_TEST(test_blob_version_too_new)
{
    /* Hand-built JSON with v=99 (above any version this build supports). */
    static const char doc[] =
        "{\"v\":99,\"mode\":1,\"key_bits\":512,"
        "\"key_n\":\"" /* 64 hex zeros = 32 bytes */
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000\","
        "\"key_d\":\""
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000\","
        "\"key_s\":\""
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000\","
        "\"ns\":[\"0\",\"0\",\"0\",\"0\",\"0\",\"0\",\"0\",\"0\"],"
        "\"ds\":[\"0\",\"0\",\"0\",\"0\",\"0\",\"0\",\"0\",\"0\"],"
        "\"ss\":[\"0\",\"0\",\"0\",\"0\",\"0\",\"0\",\"0\",\"0\"],"
        "\"globals\":{\"nonce_bits\":128,\"barrier_fill\":1,\"bit_soup\":0,\"lock_soup\":0}}";
    itb_blob512_t *b = NULL;
    ck_assert_int_eq(itb_blob512_new(&b), ITB_OK);
    itb_status_t rc = itb_blob512_import(b, doc, sizeof(doc) - 1);
    ck_assert_int_eq(rc, ITB_BLOB_VERSION_TOO_NEW);
    itb_blob512_free(b);
}
END_TEST

int main(void)
{
    Suite *s = suite_create("blob");
    TCase *tc = tcase_create("core");
    tcase_set_timeout(tc, 180);
    tcase_add_test(tc, test_blob_blob256_single_export_import_roundtrip);
    tcase_add_test(tc, test_blob_blob256_freshly_constructed_has_unset_mode);
    tcase_add_test(tc, test_blob_drop_does_not_panic);
    tcase_add_test(tc, test_blob_construct_each_width);
    tcase_add_test(tc, test_blob_blob512_single_full_matrix);
    tcase_add_test(tc, test_blob_blob512_triple_full_matrix);
    tcase_add_test(tc, test_blob_blob256_single);
    tcase_add_test(tc, test_blob_blob256_triple);
    tcase_add_test(tc, test_blob_blob128_siphash_single);
    tcase_add_test(tc, test_blob_blob128_aescmac_single);
    tcase_add_test(tc, test_blob_mode_mismatch);
    tcase_add_test(tc, test_blob_malformed);
    tcase_add_test(tc, test_blob_version_too_new);
    suite_add_tcase(s, tc);

    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int failures = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failures == 0 ? 0 : 1;
}
