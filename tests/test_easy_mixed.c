/*
 * test_easy_mixed.c — Mixed-mode Encryptor (per-slot PRF primitive
 * selection) coverage on the high-level Easy surface.
 *
 * Mirrors bindings/rust/tests/test_easy_mixed.rs one-to-one. Round-trip
 * on Single + Triple under itb_encryptor_new_mixed /
 * itb_encryptor_new_mixed3; optional dedicated lockSeed under its own
 * primitive; state-blob Export / Import; mixed-width rejection through
 * the cgo boundary; per-slot introspection accessors
 * (itb_encryptor_primitive_at, itb_encryptor_is_mixed).
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

static uint8_t *token_bytes(size_t n) {
    static uint64_t ctr = 0xFEEDFACEDEC0DED0ULL;
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

/* ─── TestMixedSingle ──────────────────────────────────────────── */

START_TEST(test_easy_mixed_single_basic_roundtrip)
{
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new_mixed("blake3", "blake2s", "areion256",
                                             NULL, 1024, "kmac256", &enc), ITB_OK);
    int is_mixed = 0;
    ck_assert_int_eq(itb_encryptor_is_mixed(enc, &is_mixed), ITB_OK);
    ck_assert_int_eq(is_mixed, 1);

    /* Single-primitive view returns "mixed" sentinel. */
    char buf[64]; size_t blen = 0;
    ck_assert_int_eq(itb_encryptor_primitive(enc, buf, sizeof(buf), &blen), ITB_OK);
    ck_assert_str_eq(buf, "mixed");

    ck_assert_int_eq(itb_encryptor_primitive_at(enc, 0, buf, sizeof(buf), &blen), ITB_OK);
    ck_assert_str_eq(buf, "blake3");
    ck_assert_int_eq(itb_encryptor_primitive_at(enc, 1, buf, sizeof(buf), &blen), ITB_OK);
    ck_assert_str_eq(buf, "blake2s");
    ck_assert_int_eq(itb_encryptor_primitive_at(enc, 2, buf, sizeof(buf), &blen), ITB_OK);
    ck_assert_str_eq(buf, "areion256");

    static const uint8_t plaintext[] = "c mixed Single roundtrip payload";
    size_t pt_len = sizeof(plaintext) - 1;
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
END_TEST

START_TEST(test_easy_mixed_single_with_dedicated_lockseed)
{
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new_mixed("blake3", "blake2s", "blake3",
                                             "areion256", 1024, "kmac256", &enc), ITB_OK);
    char buf[64]; size_t blen = 0;
    ck_assert_int_eq(itb_encryptor_primitive_at(enc, 3, buf, sizeof(buf), &blen), ITB_OK);
    ck_assert_str_eq(buf, "areion256");

    static const uint8_t plaintext[] = "c mixed Single + dedicated lockSeed payload";
    size_t pt_len = sizeof(plaintext) - 1;
    uint8_t *ct = NULL; size_t ct_len = 0;
    ck_assert_int_eq(itb_encryptor_encrypt_auth(enc, plaintext, pt_len, &ct, &ct_len), ITB_OK);
    uint8_t *pt = NULL; size_t pt_out_len = 0;
    ck_assert_int_eq(itb_encryptor_decrypt_auth(enc, ct, ct_len, &pt, &pt_out_len), ITB_OK);
    ck_assert_uint_eq(pt_out_len, pt_len);
    ck_assert_mem_eq(pt, plaintext, pt_len);

    itb_buffer_free(ct);
    itb_buffer_free(pt);
    itb_encryptor_free(enc);
}
END_TEST

START_TEST(test_easy_mixed_single_aescmac_siphash_128bit)
{
    /* SipHash-2-4 in one slot + AES-CMAC in others — 128-bit width
     * with mixed key shapes (siphash24 carries no fixed key bytes,
     * aescmac carries 16). Exercises the per-slot empty / non-empty
     * PRF-key validation in Export / Import. */
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new_mixed("aescmac", "siphash24", "aescmac",
                                             NULL, 512, "hmac-sha256", &enc), ITB_OK);
    static const uint8_t plaintext[] = "c mixed 128-bit aescmac+siphash24 mix";
    size_t pt_len = sizeof(plaintext) - 1;
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
END_TEST

/* ─── TestMixedTriple ──────────────────────────────────────────── */

START_TEST(test_easy_mixed_triple_basic_roundtrip)
{
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new_mixed3("areion256", "blake3", "blake2s",
                                              "chacha20", "blake2b256", "blake3",
                                              "blake2s", NULL,
                                              1024, "kmac256", &enc), ITB_OK);
    static const char *wants[] = {
        "areion256", "blake3", "blake2s", "chacha20",
        "blake2b256", "blake3", "blake2s",
    };
    char buf[64]; size_t blen = 0;
    for (int i = 0; i < 7; i++) {
        ck_assert_int_eq(itb_encryptor_primitive_at(enc, i, buf, sizeof(buf), &blen), ITB_OK);
        ck_assert_str_eq(buf, wants[i]);
    }

    static const uint8_t plaintext[] = "c mixed Triple roundtrip payload";
    size_t pt_len = sizeof(plaintext) - 1;
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
END_TEST

START_TEST(test_easy_mixed_triple_with_dedicated_lockseed)
{
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new_mixed3("blake3", "blake2s", "blake3", "blake2s",
                                              "blake3", "blake2s", "blake3",
                                              "areion256",
                                              1024, "kmac256", &enc), ITB_OK);
    char buf[64]; size_t blen = 0;
    ck_assert_int_eq(itb_encryptor_primitive_at(enc, 7, buf, sizeof(buf), &blen), ITB_OK);
    ck_assert_str_eq(buf, "areion256");

    /* Build a 16x-repeated plaintext to exercise multi-block paths. */
    static const char unit[] = "c mixed Triple + lockSeed payload";
    size_t unit_len = sizeof(unit) - 1;
    size_t pt_len = unit_len * 16;
    uint8_t *plaintext = (uint8_t *)malloc(pt_len);
    ck_assert_ptr_nonnull(plaintext);
    for (size_t i = 0; i < 16; i++) {
        memcpy(plaintext + i * unit_len, unit, unit_len);
    }

    uint8_t *ct = NULL; size_t ct_len = 0;
    ck_assert_int_eq(itb_encryptor_encrypt_auth(enc, plaintext, pt_len, &ct, &ct_len), ITB_OK);
    uint8_t *pt = NULL; size_t pt_out_len = 0;
    ck_assert_int_eq(itb_encryptor_decrypt_auth(enc, ct, ct_len, &pt, &pt_out_len), ITB_OK);
    ck_assert_uint_eq(pt_out_len, pt_len);
    ck_assert_mem_eq(pt, plaintext, pt_len);

    free(plaintext);
    itb_buffer_free(ct);
    itb_buffer_free(pt);
    itb_encryptor_free(enc);
}
END_TEST

/* ─── TestMixedExportImport ────────────────────────────────────── */

START_TEST(test_easy_mixed_single_export_import)
{
    itb_encryptor_t *sender = NULL;
    ck_assert_int_eq(itb_encryptor_new_mixed("blake3", "blake2s", "areion256",
                                             NULL, 1024, "kmac256", &sender), ITB_OK);
    size_t pt_len = 2048;
    uint8_t *plaintext = token_bytes(pt_len);

    uint8_t *ct = NULL; size_t ct_len = 0;
    ck_assert_int_eq(itb_encryptor_encrypt_auth(sender, plaintext, pt_len,
                                                &ct, &ct_len), ITB_OK);
    uint8_t *blob = NULL; size_t blob_len = 0;
    ck_assert_int_eq(itb_encryptor_export(sender, &blob, &blob_len), ITB_OK);
    ck_assert_uint_gt(blob_len, 0);
    itb_encryptor_free(sender);

    itb_encryptor_t *receiver = NULL;
    ck_assert_int_eq(itb_encryptor_new_mixed("blake3", "blake2s", "areion256",
                                             NULL, 1024, "kmac256", &receiver), ITB_OK);
    ck_assert_int_eq(itb_encryptor_import(receiver, blob, blob_len), ITB_OK);

    uint8_t *pt = NULL; size_t pt_out_len = 0;
    ck_assert_int_eq(itb_encryptor_decrypt_auth(receiver, ct, ct_len, &pt, &pt_out_len),
                     ITB_OK);
    ck_assert_uint_eq(pt_out_len, pt_len);
    ck_assert_mem_eq(pt, plaintext, pt_len);

    free(plaintext);
    itb_buffer_free(ct);
    itb_buffer_free(blob);
    itb_buffer_free(pt);
    itb_encryptor_free(receiver);
}
END_TEST

START_TEST(test_easy_mixed_triple_export_import_with_lockseed)
{
    static const char unit[] = "c mixed Triple + lockSeed Export/Import";
    size_t unit_len = sizeof(unit) - 1;
    size_t pt_len = unit_len * 16;
    uint8_t *plaintext = (uint8_t *)malloc(pt_len);
    ck_assert_ptr_nonnull(plaintext);
    for (size_t i = 0; i < 16; i++) {
        memcpy(plaintext + i * unit_len, unit, unit_len);
    }

    itb_encryptor_t *sender = NULL;
    ck_assert_int_eq(itb_encryptor_new_mixed3("areion256", "blake3", "blake2s",
                                              "chacha20", "blake2b256", "blake3",
                                              "blake2s", "areion256",
                                              1024, "kmac256", &sender), ITB_OK);
    uint8_t *ct = NULL; size_t ct_len = 0;
    ck_assert_int_eq(itb_encryptor_encrypt_auth(sender, plaintext, pt_len,
                                                &ct, &ct_len), ITB_OK);
    uint8_t *blob = NULL; size_t blob_len = 0;
    ck_assert_int_eq(itb_encryptor_export(sender, &blob, &blob_len), ITB_OK);
    itb_encryptor_free(sender);

    itb_encryptor_t *receiver = NULL;
    ck_assert_int_eq(itb_encryptor_new_mixed3("areion256", "blake3", "blake2s",
                                              "chacha20", "blake2b256", "blake3",
                                              "blake2s", "areion256",
                                              1024, "kmac256", &receiver), ITB_OK);
    ck_assert_int_eq(itb_encryptor_import(receiver, blob, blob_len), ITB_OK);

    uint8_t *pt = NULL; size_t pt_out_len = 0;
    ck_assert_int_eq(itb_encryptor_decrypt_auth(receiver, ct, ct_len, &pt, &pt_out_len),
                     ITB_OK);
    ck_assert_uint_eq(pt_out_len, pt_len);
    ck_assert_mem_eq(pt, plaintext, pt_len);

    free(plaintext);
    itb_buffer_free(ct);
    itb_buffer_free(blob);
    itb_buffer_free(pt);
    itb_encryptor_free(receiver);
}
END_TEST

START_TEST(test_easy_mixed_shape_mismatch)
{
    /* Mixed blob landing on a single-primitive receiver must be
     * rejected. */
    itb_encryptor_t *mixed_sender = NULL;
    ck_assert_int_eq(itb_encryptor_new_mixed("blake3", "blake2s", "blake3",
                                             NULL, 1024, "kmac256",
                                             &mixed_sender), ITB_OK);
    uint8_t *blob = NULL; size_t blob_len = 0;
    ck_assert_int_eq(itb_encryptor_export(mixed_sender, &blob, &blob_len), ITB_OK);
    itb_encryptor_free(mixed_sender);

    itb_encryptor_t *single_recv = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &single_recv), ITB_OK);
    ck_assert_int_ne(itb_encryptor_import(single_recv, blob, blob_len), ITB_OK);

    itb_buffer_free(blob);
    itb_encryptor_free(single_recv);
}
END_TEST

/* ─── TestMixedRejection ───────────────────────────────────────── */

START_TEST(test_easy_mixed_reject_mixed_width)
{
    /* Mixing 256-bit + 512-bit primitives surfaces as an error. */
    itb_encryptor_t *enc = (itb_encryptor_t *)0x1;
    itb_status_t rc = itb_encryptor_new_mixed("blake3",     /* 256-bit */
                                              "areion512",  /* 512-bit ← mismatch */
                                              "blake3",
                                              NULL, 1024, "kmac256", &enc);
    ck_assert_int_ne(rc, ITB_OK);
    ck_assert_ptr_null(enc);
}
END_TEST

START_TEST(test_easy_mixed_reject_unknown_primitive)
{
    itb_encryptor_t *enc = (itb_encryptor_t *)0x1;
    itb_status_t rc = itb_encryptor_new_mixed("no-such-primitive", "blake3", "blake3",
                                              NULL, 1024, "kmac256", &enc);
    ck_assert_int_ne(rc, ITB_OK);
    ck_assert_ptr_null(enc);
}
END_TEST

/* ─── TestMixedNonMixed ────────────────────────────────────────── */

START_TEST(test_easy_mixed_default_constructor_is_not_mixed)
{
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &enc), ITB_OK);
    int is_mixed = 1;
    ck_assert_int_eq(itb_encryptor_is_mixed(enc, &is_mixed), ITB_OK);
    ck_assert_int_eq(is_mixed, 0);

    char buf[64]; size_t blen = 0;
    for (int i = 0; i < 3; i++) {
        ck_assert_int_eq(itb_encryptor_primitive_at(enc, i, buf, sizeof(buf), &blen), ITB_OK);
        ck_assert_str_eq(buf, "blake3");
    }
    itb_encryptor_free(enc);
}
END_TEST

int main(void)
{
    Suite *s = suite_create("easy_mixed");
    TCase *tc = tcase_create("core");
    tcase_set_timeout(tc, 60);
    tcase_add_test(tc, test_easy_mixed_single_basic_roundtrip);
    tcase_add_test(tc, test_easy_mixed_single_with_dedicated_lockseed);
    tcase_add_test(tc, test_easy_mixed_single_aescmac_siphash_128bit);
    tcase_add_test(tc, test_easy_mixed_triple_basic_roundtrip);
    tcase_add_test(tc, test_easy_mixed_triple_with_dedicated_lockseed);
    tcase_add_test(tc, test_easy_mixed_single_export_import);
    tcase_add_test(tc, test_easy_mixed_triple_export_import_with_lockseed);
    tcase_add_test(tc, test_easy_mixed_shape_mismatch);
    tcase_add_test(tc, test_easy_mixed_reject_mixed_width);
    tcase_add_test(tc, test_easy_mixed_reject_unknown_primitive);
    tcase_add_test(tc, test_easy_mixed_default_constructor_is_not_mixed);
    suite_add_tcase(s, tc);

    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int failures = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failures == 0 ? 0 : 1;
}
