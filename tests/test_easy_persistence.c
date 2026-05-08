/*
 * test_easy_persistence.c — cross-process persistence round-trip tests
 * for the high-level Encryptor surface.
 *
 * Mirrors bindings/rust/tests/test_easy_persistence.rs one-to-one. The
 * itb_encryptor_export / itb_encryptor_import / itb_easy_peek_config
 * triplet is the persistence surface required for any deployment where
 * encrypt and decrypt run in different processes (network, storage,
 * backup, microservices). Without the JSON-encoded blob captured at
 * encrypt-side and re-supplied at decrypt-side, the encryptor state
 * cannot be reconstructed and the ciphertext is unreadable.
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

static size_t expected_prf_key_len(const char *name) {
    if (strcmp(name, "areion256")  == 0) return 32;
    if (strcmp(name, "areion512")  == 0) return 64;
    if (strcmp(name, "siphash24")  == 0) return 0;
    if (strcmp(name, "aescmac")    == 0) return 16;
    if (strcmp(name, "blake2b256") == 0) return 32;
    if (strcmp(name, "blake2b512") == 0) return 64;
    if (strcmp(name, "blake2s")    == 0) return 32;
    if (strcmp(name, "blake3")     == 0) return 32;
    if (strcmp(name, "chacha20")   == 0) return 32;
    ck_abort_msg("unknown hash %s", name);
    return 0;
}

static const int CANDIDATE_KB[] = {512, 1024, 2048};
#define CANDIDATE_KB_COUNT (sizeof(CANDIDATE_KB) / sizeof(CANDIDATE_KB[0]))

static const int MODES[] = {1, 3};
#define MODES_COUNT (sizeof(MODES) / sizeof(MODES[0]))

static const char *MAC_NAMES[] = {"kmac256", "hmac-sha256", "hmac-blake3"};
#define MAC_NAMES_COUNT (sizeof(MAC_NAMES) / sizeof(MAC_NAMES[0]))

/* Builds a canonical Single-mode plaintext (binary data including
 * 0x00 bytes). */
static uint8_t *canonical_plaintext_single(size_t *out_len) {
    static const char prefix[] = "any binary data, including 0x00 bytes -- ";
    size_t prefix_len = sizeof(prefix) - 1;
    size_t total = prefix_len + 256;
    uint8_t *p = (uint8_t *)malloc(total);
    ck_assert_ptr_nonnull(p);
    memcpy(p, prefix, prefix_len);
    for (size_t i = 0; i < 256; i++) {
        p[prefix_len + i] = (uint8_t)i;
    }
    *out_len = total;
    return p;
}

static uint8_t *canonical_plaintext_triple(size_t *out_len) {
    static const char prefix[] = "triple-mode persistence payload ";
    size_t prefix_len = sizeof(prefix) - 1;
    size_t total = prefix_len + 64;
    uint8_t *p = (uint8_t *)malloc(total);
    ck_assert_ptr_nonnull(p);
    memcpy(p, prefix, prefix_len);
    for (size_t i = 0; i < 64; i++) {
        p[prefix_len + i] = (uint8_t)i;
    }
    *out_len = total;
    return p;
}

/* ─── TestPersistenceRoundtrip ─────────────────────────────────── */

START_TEST(test_easy_persistence_roundtrip_all_hashes_single)
{
    size_t pt_len = 0;
    uint8_t *plaintext = canonical_plaintext_single(&pt_len);

    for (size_t hi = 0; hi < CANONICAL_HASHES_COUNT; hi++) {
        const char *name = CANONICAL_HASHES[hi].name;
        int width = CANONICAL_HASHES[hi].width;
        for (size_t ki = 0; ki < CANDIDATE_KB_COUNT; ki++) {
            int kb = CANDIDATE_KB[ki];
            if (kb % width != 0) continue;

            /* Day 1 — random encryptor. */
            itb_encryptor_t *src = NULL;
            ck_assert_int_eq(itb_encryptor_new(name, kb, "kmac256", 1, &src), ITB_OK);
            uint8_t *blob = NULL; size_t blob_len = 0;
            ck_assert_int_eq(itb_encryptor_export(src, &blob, &blob_len), ITB_OK);
            uint8_t *ct = NULL; size_t ct_len = 0;
            ck_assert_int_eq(itb_encryptor_encrypt_auth(src, plaintext, pt_len,
                                                        &ct, &ct_len), ITB_OK);
            itb_encryptor_free(src);

            /* Day 2 — restore from saved blob. */
            itb_encryptor_t *dst = NULL;
            ck_assert_int_eq(itb_encryptor_new(name, kb, "kmac256", 1, &dst), ITB_OK);
            ck_assert_int_eq(itb_encryptor_import(dst, blob, blob_len), ITB_OK);
            uint8_t *pt = NULL; size_t pt_out_len = 0;
            ck_assert_int_eq(itb_encryptor_decrypt_auth(dst, ct, ct_len,
                                                        &pt, &pt_out_len), ITB_OK);
            ck_assert_uint_eq(pt_out_len, pt_len);
            ck_assert_mem_eq(pt, plaintext, pt_len);

            itb_buffer_free(blob);
            itb_buffer_free(ct);
            itb_buffer_free(pt);
            itb_encryptor_free(dst);
        }
    }
    free(plaintext);
}
END_TEST

START_TEST(test_easy_persistence_roundtrip_all_hashes_triple)
{
    size_t pt_len = 0;
    uint8_t *plaintext = canonical_plaintext_triple(&pt_len);

    for (size_t hi = 0; hi < CANONICAL_HASHES_COUNT; hi++) {
        const char *name = CANONICAL_HASHES[hi].name;
        int width = CANONICAL_HASHES[hi].width;
        for (size_t ki = 0; ki < CANDIDATE_KB_COUNT; ki++) {
            int kb = CANDIDATE_KB[ki];
            if (kb % width != 0) continue;

            itb_encryptor_t *src = NULL;
            ck_assert_int_eq(itb_encryptor_new(name, kb, "kmac256", 3, &src), ITB_OK);
            uint8_t *blob = NULL; size_t blob_len = 0;
            ck_assert_int_eq(itb_encryptor_export(src, &blob, &blob_len), ITB_OK);
            uint8_t *ct = NULL; size_t ct_len = 0;
            ck_assert_int_eq(itb_encryptor_encrypt_auth(src, plaintext, pt_len,
                                                        &ct, &ct_len), ITB_OK);
            itb_encryptor_free(src);

            itb_encryptor_t *dst = NULL;
            ck_assert_int_eq(itb_encryptor_new(name, kb, "kmac256", 3, &dst), ITB_OK);
            ck_assert_int_eq(itb_encryptor_import(dst, blob, blob_len), ITB_OK);
            uint8_t *pt = NULL; size_t pt_out_len = 0;
            ck_assert_int_eq(itb_encryptor_decrypt_auth(dst, ct, ct_len,
                                                        &pt, &pt_out_len), ITB_OK);
            ck_assert_uint_eq(pt_out_len, pt_len);
            ck_assert_mem_eq(pt, plaintext, pt_len);

            itb_buffer_free(blob);
            itb_buffer_free(ct);
            itb_buffer_free(pt);
            itb_encryptor_free(dst);
        }
    }
    free(plaintext);
}
END_TEST

START_TEST(test_easy_persistence_roundtrip_with_lock_seed)
{
    /* Activating LockSeed grows the encryptor to 4 (Single) or 8
     * (Triple) seed slots; the exported blob carries the dedicated
     * lockSeed material, and itb_encryptor_import on a fresh encryptor
     * restores the seed slot AND auto-couples LockSoup + BitSoup
     * overlays. */
    static const char prefix[] = "lockseed payload ";
    size_t prefix_len = sizeof(prefix) - 1;
    size_t pt_len = prefix_len + 32;
    uint8_t *plaintext = (uint8_t *)malloc(pt_len);
    ck_assert_ptr_nonnull(plaintext);
    memcpy(plaintext, prefix, prefix_len);
    for (size_t i = 0; i < 32; i++) plaintext[prefix_len + i] = (uint8_t)i;

    static const struct { int mode; int expected_count; } CASES[] = {
        {1, 4}, {3, 8},
    };
    for (size_t k = 0; k < sizeof(CASES) / sizeof(CASES[0]); k++) {
        int mode = CASES[k].mode;
        int expected = CASES[k].expected_count;

        itb_encryptor_t *src = NULL;
        ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", mode, &src), ITB_OK);
        ck_assert_int_eq(itb_encryptor_set_lock_seed(src, 1), ITB_OK);
        int sc = 0;
        ck_assert_int_eq(itb_encryptor_seed_count(src, &sc), ITB_OK);
        ck_assert_int_eq(sc, expected);

        uint8_t *blob = NULL; size_t blob_len = 0;
        ck_assert_int_eq(itb_encryptor_export(src, &blob, &blob_len), ITB_OK);
        uint8_t *ct = NULL; size_t ct_len = 0;
        ck_assert_int_eq(itb_encryptor_encrypt_auth(src, plaintext, pt_len,
                                                    &ct, &ct_len), ITB_OK);
        itb_encryptor_free(src);

        itb_encryptor_t *dst = NULL;
        ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", mode, &dst), ITB_OK);
        ck_assert_int_eq(itb_encryptor_seed_count(dst, &sc), ITB_OK);
        ck_assert_int_eq(sc, expected - 1);
        ck_assert_int_eq(itb_encryptor_import(dst, blob, blob_len), ITB_OK);
        ck_assert_int_eq(itb_encryptor_seed_count(dst, &sc), ITB_OK);
        ck_assert_int_eq(sc, expected);

        uint8_t *pt = NULL; size_t pt_out_len = 0;
        ck_assert_int_eq(itb_encryptor_decrypt_auth(dst, ct, ct_len,
                                                    &pt, &pt_out_len), ITB_OK);
        ck_assert_uint_eq(pt_out_len, pt_len);
        ck_assert_mem_eq(pt, plaintext, pt_len);

        itb_buffer_free(blob);
        itb_buffer_free(ct);
        itb_buffer_free(pt);
        itb_encryptor_free(dst);
    }
    free(plaintext);
}
END_TEST

START_TEST(test_easy_persistence_roundtrip_with_full_config)
{
    /* Per-instance configuration knobs (NonceBits, BarrierFill, BitSoup,
     * LockSoup) round-trip through the state blob along with the seed
     * material — no manual mirror set_*() calls required on the
     * receiver. */
    static const char prefix[] = "full-config persistence ";
    size_t prefix_len = sizeof(prefix) - 1;
    size_t pt_len = prefix_len + 64;
    uint8_t *plaintext = (uint8_t *)malloc(pt_len);
    ck_assert_ptr_nonnull(plaintext);
    memcpy(plaintext, prefix, prefix_len);
    for (size_t i = 0; i < 64; i++) plaintext[prefix_len + i] = (uint8_t)i;

    itb_encryptor_t *src = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &src), ITB_OK);
    ck_assert_int_eq(itb_encryptor_set_nonce_bits(src, 512), ITB_OK);
    ck_assert_int_eq(itb_encryptor_set_barrier_fill(src, 4), ITB_OK);
    ck_assert_int_eq(itb_encryptor_set_bit_soup(src, 1), ITB_OK);
    ck_assert_int_eq(itb_encryptor_set_lock_soup(src, 1), ITB_OK);

    uint8_t *blob = NULL; size_t blob_len = 0;
    ck_assert_int_eq(itb_encryptor_export(src, &blob, &blob_len), ITB_OK);
    uint8_t *ct = NULL; size_t ct_len = 0;
    ck_assert_int_eq(itb_encryptor_encrypt_auth(src, plaintext, pt_len,
                                                &ct, &ct_len), ITB_OK);
    itb_encryptor_free(src);

    /* Receiver — fresh encryptor without any mirror set_*() calls. */
    itb_encryptor_t *dst = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &dst), ITB_OK);
    int nb = 0;
    ck_assert_int_eq(itb_encryptor_nonce_bits(dst, &nb), ITB_OK);
    ck_assert_int_eq(nb, 128); /* default before Import */
    ck_assert_int_eq(itb_encryptor_import(dst, blob, blob_len), ITB_OK);
    ck_assert_int_eq(itb_encryptor_nonce_bits(dst, &nb), ITB_OK);
    ck_assert_int_eq(nb, 512); /* restored from blob */
    int hs = 0;
    ck_assert_int_eq(itb_encryptor_header_size(dst, &hs), ITB_OK);
    ck_assert_int_eq(hs, 68);

    uint8_t *pt = NULL; size_t pt_out_len = 0;
    ck_assert_int_eq(itb_encryptor_decrypt_auth(dst, ct, ct_len,
                                                &pt, &pt_out_len), ITB_OK);
    ck_assert_uint_eq(pt_out_len, pt_len);
    ck_assert_mem_eq(pt, plaintext, pt_len);

    free(plaintext);
    itb_buffer_free(blob);
    itb_buffer_free(ct);
    itb_buffer_free(pt);
    itb_encryptor_free(dst);
}
END_TEST

START_TEST(test_easy_persistence_roundtrip_barrier_fill_receiver_priority)
{
    /* BarrierFill is asymmetric — the receiver does not need the same
     * margin as the sender. When the receiver explicitly installs a
     * non-default BarrierFill before Import, that choice takes
     * priority over the blob's barrier_fill. */
    static const uint8_t plaintext[] = "barrier-fill priority";
    size_t pt_len = sizeof(plaintext) - 1;

    itb_encryptor_t *src = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &src), ITB_OK);
    ck_assert_int_eq(itb_encryptor_set_barrier_fill(src, 4), ITB_OK);
    uint8_t *blob = NULL; size_t blob_len = 0;
    ck_assert_int_eq(itb_encryptor_export(src, &blob, &blob_len), ITB_OK);
    uint8_t *ct = NULL; size_t ct_len = 0;
    ck_assert_int_eq(itb_encryptor_encrypt_auth(src, plaintext, pt_len,
                                                &ct, &ct_len), ITB_OK);
    itb_encryptor_free(src);

    /* Receiver pre-sets BarrierFill=8; Import must NOT downgrade it. */
    itb_encryptor_t *dst1 = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &dst1), ITB_OK);
    ck_assert_int_eq(itb_encryptor_set_barrier_fill(dst1, 8), ITB_OK);
    ck_assert_int_eq(itb_encryptor_import(dst1, blob, blob_len), ITB_OK);
    uint8_t *pt1 = NULL; size_t pt1_len = 0;
    ck_assert_int_eq(itb_encryptor_decrypt_auth(dst1, ct, ct_len, &pt1, &pt1_len), ITB_OK);
    ck_assert_mem_eq(pt1, plaintext, pt_len);

    /* Receiver that did NOT pre-set BarrierFill picks up blob value. */
    itb_encryptor_t *dst2 = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &dst2), ITB_OK);
    ck_assert_int_eq(itb_encryptor_import(dst2, blob, blob_len), ITB_OK);
    uint8_t *pt2 = NULL; size_t pt2_len = 0;
    ck_assert_int_eq(itb_encryptor_decrypt_auth(dst2, ct, ct_len, &pt2, &pt2_len), ITB_OK);
    ck_assert_mem_eq(pt2, plaintext, pt_len);

    itb_buffer_free(blob);
    itb_buffer_free(ct);
    itb_buffer_free(pt1);
    itb_buffer_free(pt2);
    itb_encryptor_free(dst1);
    itb_encryptor_free(dst2);
}
END_TEST

/* ─── TestPeekConfig ───────────────────────────────────────────── */

START_TEST(test_easy_persistence_peek_recovers_metadata)
{
    for (size_t hi = 0; hi < CANONICAL_HASHES_COUNT; hi++) {
        const char *name = CANONICAL_HASHES[hi].name;
        int width = CANONICAL_HASHES[hi].width;
        for (size_t ki = 0; ki < CANDIDATE_KB_COUNT; ki++) {
            int kb = CANDIDATE_KB[ki];
            if (kb % width != 0) continue;
            for (size_t mi = 0; mi < MODES_COUNT; mi++) {
                for (size_t mac_i = 0; mac_i < MAC_NAMES_COUNT; mac_i++) {
                    itb_encryptor_t *enc = NULL;
                    ck_assert_int_eq(itb_encryptor_new(name, kb, MAC_NAMES[mac_i],
                                                       MODES[mi], &enc), ITB_OK);
                    uint8_t *blob = NULL; size_t blob_len = 0;
                    ck_assert_int_eq(itb_encryptor_export(enc, &blob, &blob_len), ITB_OK);
                    itb_encryptor_free(enc);

                    char prim[64]; size_t prim_len = 0;
                    char mac[64]; size_t mac_len = 0;
                    int kb2 = 0, mode2 = 0;
                    ck_assert_int_eq(itb_easy_peek_config(blob, blob_len,
                                                          prim, sizeof(prim), &prim_len,
                                                          &kb2, &mode2,
                                                          mac, sizeof(mac), &mac_len), ITB_OK);
                    ck_assert_str_eq(prim, name);
                    ck_assert_int_eq(kb2, kb);
                    ck_assert_int_eq(mode2, MODES[mi]);
                    ck_assert_str_eq(mac, MAC_NAMES[mac_i]);

                    itb_buffer_free(blob);
                }
            }
        }
    }
}
END_TEST

START_TEST(test_easy_persistence_peek_malformed_blob)
{
    static const struct { const char *data; size_t len; } CASES[] = {
        {"not json",   8},
        {"",           0},
        {"{}",         2},
        {"{\"v\":1}",  7},
    };
    for (size_t i = 0; i < sizeof(CASES) / sizeof(CASES[0]); i++) {
        char prim[64]; size_t prim_len = 0;
        char mac[64]; size_t mac_len = 0;
        int kb = 0, mode = 0;
        itb_status_t rc = itb_easy_peek_config(CASES[i].data, CASES[i].len,
                                               prim, sizeof(prim), &prim_len,
                                               &kb, &mode,
                                               mac, sizeof(mac), &mac_len);
        ck_assert_int_eq(rc, ITB_EASY_MALFORMED);
    }
}
END_TEST

START_TEST(test_easy_persistence_peek_too_new_version)
{
    /* Hand-craft a blob with v=99; PeekConfig conflates "too-new
     * version" with the broader malformed-shape bucket and surfaces
     * ITB_EASY_MALFORMED. The dedicated ITB_EASY_VERSION_TOO_NEW is
     * reserved for the Import path. */
    static const char blob[] = "{\"v\":99,\"kind\":\"itb-easy\"}";
    char prim[64]; size_t prim_len = 0;
    char mac[64]; size_t mac_len = 0;
    int kb = 0, mode = 0;
    itb_status_t rc = itb_easy_peek_config(blob, sizeof(blob) - 1,
                                           prim, sizeof(prim), &prim_len,
                                           &kb, &mode,
                                           mac, sizeof(mac), &mac_len);
    ck_assert_int_eq(rc, ITB_EASY_MALFORMED);
}
END_TEST

/* ─── TestImportMismatch ───────────────────────────────────────── */

static void make_baseline_blob(uint8_t **out_blob, size_t *out_len)
{
    itb_encryptor_t *src = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &src), ITB_OK);
    ck_assert_int_eq(itb_encryptor_export(src, out_blob, out_len), ITB_OK);
    itb_encryptor_free(src);
}

START_TEST(test_easy_persistence_import_mismatch_primitive)
{
    uint8_t *blob = NULL; size_t blob_len = 0;
    make_baseline_blob(&blob, &blob_len);

    itb_encryptor_t *dst = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake2s", 1024, "kmac256", 1, &dst), ITB_OK);
    ck_assert_int_eq(itb_encryptor_import(dst, blob, blob_len), ITB_EASY_MISMATCH);
    char fbuf[64]; size_t flen = 0;
    ck_assert_int_eq(itb_easy_last_mismatch_field(fbuf, sizeof(fbuf), &flen), ITB_OK);
    ck_assert_str_eq(fbuf, "primitive");

    itb_buffer_free(blob);
    itb_encryptor_free(dst);
}
END_TEST

START_TEST(test_easy_persistence_import_mismatch_key_bits)
{
    uint8_t *blob = NULL; size_t blob_len = 0;
    make_baseline_blob(&blob, &blob_len);

    itb_encryptor_t *dst = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 2048, "kmac256", 1, &dst), ITB_OK);
    ck_assert_int_eq(itb_encryptor_import(dst, blob, blob_len), ITB_EASY_MISMATCH);
    char fbuf[64]; size_t flen = 0;
    ck_assert_int_eq(itb_easy_last_mismatch_field(fbuf, sizeof(fbuf), &flen), ITB_OK);
    ck_assert_str_eq(fbuf, "key_bits");

    itb_buffer_free(blob);
    itb_encryptor_free(dst);
}
END_TEST

START_TEST(test_easy_persistence_import_mismatch_mode)
{
    uint8_t *blob = NULL; size_t blob_len = 0;
    make_baseline_blob(&blob, &blob_len);

    itb_encryptor_t *dst = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 3, &dst), ITB_OK);
    ck_assert_int_eq(itb_encryptor_import(dst, blob, blob_len), ITB_EASY_MISMATCH);
    char fbuf[64]; size_t flen = 0;
    ck_assert_int_eq(itb_easy_last_mismatch_field(fbuf, sizeof(fbuf), &flen), ITB_OK);
    ck_assert_str_eq(fbuf, "mode");

    itb_buffer_free(blob);
    itb_encryptor_free(dst);
}
END_TEST

START_TEST(test_easy_persistence_import_mismatch_mac)
{
    uint8_t *blob = NULL; size_t blob_len = 0;
    make_baseline_blob(&blob, &blob_len);

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

/* ─── TestImportMalformed ──────────────────────────────────────── */

START_TEST(test_easy_persistence_import_malformed_json)
{
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &enc), ITB_OK);
    static const char blob[] = "this is not json";
    ck_assert_int_eq(itb_encryptor_import(enc, blob, sizeof(blob) - 1),
                     ITB_EASY_MALFORMED);
    itb_encryptor_free(enc);
}
END_TEST

START_TEST(test_easy_persistence_import_too_new_version)
{
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &enc), ITB_OK);
    static const char blob[] = "{\"v\":99,\"kind\":\"itb-easy\"}";
    ck_assert_int_eq(itb_encryptor_import(enc, blob, sizeof(blob) - 1),
                     ITB_EASY_VERSION_TOO_NEW);
    itb_encryptor_free(enc);
}
END_TEST

START_TEST(test_easy_persistence_import_wrong_kind)
{
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &enc), ITB_OK);
    static const char blob[] = "{\"v\":1,\"kind\":\"not-itb-easy\"}";
    ck_assert_int_eq(itb_encryptor_import(enc, blob, sizeof(blob) - 1),
                     ITB_EASY_MALFORMED);
    itb_encryptor_free(enc);
}
END_TEST

/* ─── TestMaterialGetters ──────────────────────────────────────── */

START_TEST(test_easy_persistence_prf_key_lengths_per_primitive)
{
    for (size_t hi = 0; hi < CANONICAL_HASHES_COUNT; hi++) {
        const char *name = CANONICAL_HASHES[hi].name;
        int width = CANONICAL_HASHES[hi].width;
        for (size_t ki = 0; ki < CANDIDATE_KB_COUNT; ki++) {
            int kb = CANDIDATE_KB[ki];
            if (kb % width != 0) continue;

            itb_encryptor_t *enc = NULL;
            ck_assert_int_eq(itb_encryptor_new(name, kb, "kmac256", 1, &enc), ITB_OK);

            int has_keys = -1;
            ck_assert_int_eq(itb_encryptor_has_prf_keys(enc, &has_keys), ITB_OK);

            if (strcmp(name, "siphash24") == 0) {
                ck_assert_int_eq(has_keys, 0);
                /* prf_key request on siphash24 is rejected. */
                uint8_t buf[64]; size_t blen = 0;
                itb_status_t rc = itb_encryptor_prf_key(enc, 0, buf, sizeof(buf), &blen);
                ck_assert_int_ne(rc, ITB_OK);
            } else {
                ck_assert_int_eq(has_keys, 1);
                int sc = 0;
                ck_assert_int_eq(itb_encryptor_seed_count(enc, &sc), ITB_OK);
                for (int slot = 0; slot < sc; slot++) {
                    uint8_t buf[64]; size_t blen = 0;
                    ck_assert_int_eq(itb_encryptor_prf_key(enc, slot, buf, sizeof(buf), &blen),
                                     ITB_OK);
                    ck_assert_uint_eq(blen, expected_prf_key_len(name));
                }
            }
            itb_encryptor_free(enc);
        }
    }
}
END_TEST

START_TEST(test_easy_persistence_seed_components_lengths_per_key_bits)
{
    for (size_t hi = 0; hi < CANONICAL_HASHES_COUNT; hi++) {
        const char *name = CANONICAL_HASHES[hi].name;
        int width = CANONICAL_HASHES[hi].width;
        for (size_t ki = 0; ki < CANDIDATE_KB_COUNT; ki++) {
            int kb = CANDIDATE_KB[ki];
            if (kb % width != 0) continue;

            itb_encryptor_t *enc = NULL;
            ck_assert_int_eq(itb_encryptor_new(name, kb, "kmac256", 1, &enc), ITB_OK);
            int sc = 0;
            ck_assert_int_eq(itb_encryptor_seed_count(enc, &sc), ITB_OK);
            for (int slot = 0; slot < sc; slot++) {
                uint64_t comps[32]; size_t cn = 0;
                ck_assert_int_eq(itb_encryptor_seed_components(enc, slot, comps, 32, &cn),
                                 ITB_OK);
                ck_assert_uint_eq(cn * 64u, (size_t)kb);
            }
            itb_encryptor_free(enc);
        }
    }
}
END_TEST

START_TEST(test_easy_persistence_mac_key_present)
{
    for (size_t mi = 0; mi < MAC_NAMES_COUNT; mi++) {
        itb_encryptor_t *enc = NULL;
        ck_assert_int_eq(itb_encryptor_new("blake3", 1024, MAC_NAMES[mi], 1, &enc), ITB_OK);
        uint8_t buf[256]; size_t blen = 0;
        ck_assert_int_eq(itb_encryptor_mac_key(enc, buf, sizeof(buf), &blen), ITB_OK);
        ck_assert_uint_gt(blen, 0);
        itb_encryptor_free(enc);
    }
}
END_TEST

START_TEST(test_easy_persistence_seed_components_out_of_range)
{
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &enc), ITB_OK);
    int sc = 0;
    ck_assert_int_eq(itb_encryptor_seed_count(enc, &sc), ITB_OK);
    ck_assert_int_eq(sc, 3);

    uint64_t comps[32]; size_t cn = 0;
    ck_assert_int_eq(itb_encryptor_seed_components(enc, 3, comps, 32, &cn), ITB_BAD_INPUT);
    ck_assert_int_eq(itb_encryptor_seed_components(enc, -1, comps, 32, &cn), ITB_BAD_INPUT);

    itb_encryptor_free(enc);
}
END_TEST

int main(void)
{
    Suite *s = suite_create("easy_persistence");
    TCase *tc = tcase_create("core");
    tcase_set_timeout(tc, 300);
    tcase_add_test(tc, test_easy_persistence_roundtrip_all_hashes_single);
    tcase_add_test(tc, test_easy_persistence_roundtrip_all_hashes_triple);
    tcase_add_test(tc, test_easy_persistence_roundtrip_with_lock_seed);
    tcase_add_test(tc, test_easy_persistence_roundtrip_with_full_config);
    tcase_add_test(tc, test_easy_persistence_roundtrip_barrier_fill_receiver_priority);
    tcase_add_test(tc, test_easy_persistence_peek_recovers_metadata);
    tcase_add_test(tc, test_easy_persistence_peek_malformed_blob);
    tcase_add_test(tc, test_easy_persistence_peek_too_new_version);
    tcase_add_test(tc, test_easy_persistence_import_mismatch_primitive);
    tcase_add_test(tc, test_easy_persistence_import_mismatch_key_bits);
    tcase_add_test(tc, test_easy_persistence_import_mismatch_mode);
    tcase_add_test(tc, test_easy_persistence_import_mismatch_mac);
    tcase_add_test(tc, test_easy_persistence_import_malformed_json);
    tcase_add_test(tc, test_easy_persistence_import_too_new_version);
    tcase_add_test(tc, test_easy_persistence_import_wrong_kind);
    tcase_add_test(tc, test_easy_persistence_prf_key_lengths_per_primitive);
    tcase_add_test(tc, test_easy_persistence_seed_components_lengths_per_key_bits);
    tcase_add_test(tc, test_easy_persistence_mac_key_present);
    tcase_add_test(tc, test_easy_persistence_seed_components_out_of_range);
    suite_add_tcase(s, tc);

    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int failures = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failures == 0 ? 0 : 1;
}
