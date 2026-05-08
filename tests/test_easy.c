/*
 * test_easy.c — high-level Encryptor (Easy Mode) smoke coverage.
 *
 * Mirrors bindings/rust/tests/test_easy.rs one-to-one. Confirms the
 * Encryptor surface round-trips plaintext under Single + Triple
 * Ouroboros, authenticates on tampered ciphertext, survives the
 * export / import cycle on a fresh encryptor, and exposes the
 * read-only field accessors with the correct values.
 *
 * Each Rust `#[test] fn` becomes a single START_TEST / END_TEST block
 * here; per-binary fork() isolation gives every test a fresh libitb
 * global state without an in-process serial lock.
 */

#include <check.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "itb.h"

static const uint8_t PLAINTEXT[] =
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
#define PLAINTEXT_LEN ((size_t)(sizeof(PLAINTEXT) - 1))

START_TEST(test_easy_single_roundtrip_blake3_kmac256)
{
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &enc), ITB_OK);

    uint8_t *ct = NULL; size_t ct_len = 0;
    ck_assert_int_eq(itb_encryptor_encrypt(enc, PLAINTEXT, PLAINTEXT_LEN,
                                           &ct, &ct_len), ITB_OK);
    ck_assert_uint_gt(ct_len, 0);
    /* Ciphertext must differ from plaintext. */
    if (ct_len == PLAINTEXT_LEN) {
        ck_assert_int_ne(memcmp(ct, PLAINTEXT, PLAINTEXT_LEN), 0);
    }

    uint8_t *pt = NULL; size_t pt_len = 0;
    ck_assert_int_eq(itb_encryptor_decrypt(enc, ct, ct_len, &pt, &pt_len), ITB_OK);
    ck_assert_uint_eq(pt_len, PLAINTEXT_LEN);
    ck_assert_mem_eq(pt, PLAINTEXT, PLAINTEXT_LEN);

    /* Read-only accessors reflect constructor arguments. */
    char nbuf[64]; size_t nlen = 0;
    ck_assert_int_eq(itb_encryptor_primitive(enc, nbuf, sizeof(nbuf), &nlen), ITB_OK);
    ck_assert_str_eq(nbuf, "blake3");

    int kb = 0;
    ck_assert_int_eq(itb_encryptor_key_bits(enc, &kb), ITB_OK);
    ck_assert_int_eq(kb, 1024);

    int mode = 0;
    ck_assert_int_eq(itb_encryptor_mode(enc, &mode), ITB_OK);
    ck_assert_int_eq(mode, 1);

    char mbuf[64]; size_t mlen = 0;
    ck_assert_int_eq(itb_encryptor_mac_name(enc, mbuf, sizeof(mbuf), &mlen), ITB_OK);
    ck_assert_str_eq(mbuf, "kmac256");

    int is_mixed = 1;
    ck_assert_int_eq(itb_encryptor_is_mixed(enc, &is_mixed), ITB_OK);
    ck_assert_int_eq(is_mixed, 0);

    int seed_count = 0;
    ck_assert_int_eq(itb_encryptor_seed_count(enc, &seed_count), ITB_OK);
    ck_assert_int_eq(seed_count, 3);

    itb_buffer_free(ct);
    itb_buffer_free(pt);
    itb_encryptor_free(enc);
}
END_TEST

START_TEST(test_easy_triple_roundtrip_areion512_kmac256)
{
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new("areion512", 2048, "kmac256", 3, &enc), ITB_OK);

    uint8_t *ct = NULL; size_t ct_len = 0;
    ck_assert_int_eq(itb_encryptor_encrypt(enc, PLAINTEXT, PLAINTEXT_LEN,
                                           &ct, &ct_len), ITB_OK);
    uint8_t *pt = NULL; size_t pt_len = 0;
    ck_assert_int_eq(itb_encryptor_decrypt(enc, ct, ct_len, &pt, &pt_len), ITB_OK);
    ck_assert_uint_eq(pt_len, PLAINTEXT_LEN);
    ck_assert_mem_eq(pt, PLAINTEXT, PLAINTEXT_LEN);

    char nbuf[64]; size_t nlen = 0;
    ck_assert_int_eq(itb_encryptor_primitive(enc, nbuf, sizeof(nbuf), &nlen), ITB_OK);
    ck_assert_str_eq(nbuf, "areion512");

    int mode = 0;
    ck_assert_int_eq(itb_encryptor_mode(enc, &mode), ITB_OK);
    ck_assert_int_eq(mode, 3);

    int seed_count = 0;
    ck_assert_int_eq(itb_encryptor_seed_count(enc, &seed_count), ITB_OK);
    ck_assert_int_eq(seed_count, 7);

    itb_buffer_free(ct);
    itb_buffer_free(pt);
    itb_encryptor_free(enc);
}
END_TEST

START_TEST(test_easy_auth_roundtrip_single)
{
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &enc), ITB_OK);

    uint8_t *ct = NULL; size_t ct_len = 0;
    ck_assert_int_eq(itb_encryptor_encrypt_auth(enc, PLAINTEXT, PLAINTEXT_LEN,
                                                &ct, &ct_len), ITB_OK);
    uint8_t *pt = NULL; size_t pt_len = 0;
    ck_assert_int_eq(itb_encryptor_decrypt_auth(enc, ct, ct_len, &pt, &pt_len), ITB_OK);
    ck_assert_uint_eq(pt_len, PLAINTEXT_LEN);
    ck_assert_mem_eq(pt, PLAINTEXT, PLAINTEXT_LEN);

    itb_buffer_free(ct);
    itb_buffer_free(pt);
    itb_encryptor_free(enc);
}
END_TEST

START_TEST(test_easy_auth_decrypt_tampered_fails_with_mac_failure)
{
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &enc), ITB_OK);

    uint8_t *ct = NULL; size_t ct_len = 0;
    ck_assert_int_eq(itb_encryptor_encrypt_auth(enc, PLAINTEXT, PLAINTEXT_LEN,
                                                &ct, &ct_len), ITB_OK);
    /* Flip 256 bytes immediately past the dynamic header — sits inside
     * the structured payload and is reliably MAC-covered. */
    int hsize = 0;
    ck_assert_int_eq(itb_encryptor_header_size(enc, &hsize), ITB_OK);
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
    itb_encryptor_free(enc);
}
END_TEST

START_TEST(test_easy_export_import_roundtrip)
{
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &enc), ITB_OK);

    uint8_t *ct = NULL; size_t ct_len = 0;
    ck_assert_int_eq(itb_encryptor_encrypt_auth(enc, PLAINTEXT, PLAINTEXT_LEN,
                                                &ct, &ct_len), ITB_OK);
    uint8_t *blob = NULL; size_t blob_len = 0;
    ck_assert_int_eq(itb_encryptor_export(enc, &blob, &blob_len), ITB_OK);
    ck_assert_uint_gt(blob_len, 0);

    /* Peek-config the saved blob and reconstruct a fresh encryptor. */
    char prim[64]; size_t prim_len = 0;
    char mac[64]; size_t mac_len = 0;
    int kb = 0, mode = 0;
    ck_assert_int_eq(itb_easy_peek_config(blob, blob_len,
                                          prim, sizeof(prim), &prim_len,
                                          &kb, &mode,
                                          mac, sizeof(mac), &mac_len), ITB_OK);
    ck_assert_str_eq(prim, "blake3");
    ck_assert_int_eq(kb, 1024);
    ck_assert_int_eq(mode, 1);
    ck_assert_str_eq(mac, "kmac256");

    itb_encryptor_t *dec = NULL;
    ck_assert_int_eq(itb_encryptor_new(prim, kb, mac, mode, &dec), ITB_OK);
    ck_assert_int_eq(itb_encryptor_import(dec, blob, blob_len), ITB_OK);

    uint8_t *pt = NULL; size_t pt_len = 0;
    ck_assert_int_eq(itb_encryptor_decrypt_auth(dec, ct, ct_len, &pt, &pt_len), ITB_OK);
    ck_assert_uint_eq(pt_len, PLAINTEXT_LEN);
    ck_assert_mem_eq(pt, PLAINTEXT, PLAINTEXT_LEN);

    itb_buffer_free(ct);
    itb_buffer_free(blob);
    itb_buffer_free(pt);
    itb_encryptor_free(enc);
    itb_encryptor_free(dec);
}
END_TEST

START_TEST(test_easy_peek_config_returns_correct_tuple)
{
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new("areion512", 2048, "hmac-blake3", 3, &enc), ITB_OK);
    uint8_t *blob = NULL; size_t blob_len = 0;
    ck_assert_int_eq(itb_encryptor_export(enc, &blob, &blob_len), ITB_OK);

    char prim[64]; size_t prim_len = 0;
    char mac[64]; size_t mac_len = 0;
    int kb = 0, mode = 0;
    ck_assert_int_eq(itb_easy_peek_config(blob, blob_len,
                                          prim, sizeof(prim), &prim_len,
                                          &kb, &mode,
                                          mac, sizeof(mac), &mac_len), ITB_OK);
    ck_assert_str_eq(prim, "areion512");
    ck_assert_int_eq(kb, 2048);
    ck_assert_int_eq(mode, 3);
    ck_assert_str_eq(mac, "hmac-blake3");

    itb_buffer_free(blob);
    itb_encryptor_free(enc);
}
END_TEST

START_TEST(test_easy_mixed_single_three_same_width_primitives)
{
    /* areion256 / blake3 / blake2s — all 256-bit; key_bits=1024 is a
     * multiple of 256. The Mixed-Single constructor accepts the
     * trio. */
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new_mixed("areion256", "blake3", "blake2s",
                                             NULL, 1024, "kmac256", &enc), ITB_OK);
    int is_mixed = 0;
    ck_assert_int_eq(itb_encryptor_is_mixed(enc, &is_mixed), ITB_OK);
    ck_assert_int_eq(is_mixed, 1);

    char buf[64]; size_t blen = 0;
    ck_assert_int_eq(itb_encryptor_primitive_at(enc, 0, buf, sizeof(buf), &blen), ITB_OK);
    ck_assert_str_eq(buf, "areion256");
    ck_assert_int_eq(itb_encryptor_primitive_at(enc, 1, buf, sizeof(buf), &blen), ITB_OK);
    ck_assert_str_eq(buf, "blake3");
    ck_assert_int_eq(itb_encryptor_primitive_at(enc, 2, buf, sizeof(buf), &blen), ITB_OK);
    ck_assert_str_eq(buf, "blake2s");

    uint8_t *ct = NULL; size_t ct_len = 0;
    ck_assert_int_eq(itb_encryptor_encrypt_auth(enc, PLAINTEXT, PLAINTEXT_LEN,
                                                &ct, &ct_len), ITB_OK);
    uint8_t *pt = NULL; size_t pt_len = 0;
    ck_assert_int_eq(itb_encryptor_decrypt_auth(enc, ct, ct_len, &pt, &pt_len), ITB_OK);
    ck_assert_uint_eq(pt_len, PLAINTEXT_LEN);
    ck_assert_mem_eq(pt, PLAINTEXT, PLAINTEXT_LEN);

    itb_buffer_free(ct);
    itb_buffer_free(pt);
    itb_encryptor_free(enc);
}
END_TEST

START_TEST(test_easy_invalid_mode_rejected)
{
    itb_encryptor_t *enc = (itb_encryptor_t *)0x1;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 2, &enc),
                     ITB_BAD_INPUT);
    ck_assert_ptr_null(enc);
}
END_TEST

START_TEST(test_easy_close_is_idempotent)
{
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &enc), ITB_OK);
    ck_assert_int_eq(itb_encryptor_close(enc), ITB_OK);
    ck_assert_int_eq(itb_encryptor_close(enc), ITB_OK);
    itb_encryptor_free(enc);
}
END_TEST

START_TEST(test_easy_header_size_matches_nonce_bits)
{
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &enc), ITB_OK);
    int nb = 0;
    ck_assert_int_eq(itb_encryptor_nonce_bits(enc, &nb), ITB_OK);
    int hs = 0;
    ck_assert_int_eq(itb_encryptor_header_size(enc, &hs), ITB_OK);
    /* header = nonce(N) + width(2) + height(2) */
    ck_assert_int_eq(hs, nb / 8 + 4);
    itb_encryptor_free(enc);
}
END_TEST

START_TEST(test_easy_parse_chunk_len_matches_chunk_length)
{
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &enc), ITB_OK);

    uint8_t *ct = NULL; size_t ct_len = 0;
    ck_assert_int_eq(itb_encryptor_encrypt(enc, PLAINTEXT, PLAINTEXT_LEN,
                                           &ct, &ct_len), ITB_OK);
    int hs = 0;
    ck_assert_int_eq(itb_encryptor_header_size(enc, &hs), ITB_OK);
    size_t parsed = 0;
    ck_assert_int_eq(itb_encryptor_parse_chunk_len(enc, ct, (size_t)hs, &parsed), ITB_OK);
    ck_assert_uint_eq(parsed, ct_len);

    itb_buffer_free(ct);
    itb_encryptor_free(enc);
}
END_TEST

int main(void)
{
    Suite *s = suite_create("easy");
    TCase *tc = tcase_create("core");
    tcase_set_timeout(tc, 60);
    tcase_add_test(tc, test_easy_single_roundtrip_blake3_kmac256);
    tcase_add_test(tc, test_easy_triple_roundtrip_areion512_kmac256);
    tcase_add_test(tc, test_easy_auth_roundtrip_single);
    tcase_add_test(tc, test_easy_auth_decrypt_tampered_fails_with_mac_failure);
    tcase_add_test(tc, test_easy_export_import_roundtrip);
    tcase_add_test(tc, test_easy_peek_config_returns_correct_tuple);
    tcase_add_test(tc, test_easy_mixed_single_three_same_width_primitives);
    tcase_add_test(tc, test_easy_invalid_mode_rejected);
    tcase_add_test(tc, test_easy_close_is_idempotent);
    tcase_add_test(tc, test_easy_header_size_matches_nonce_bits);
    tcase_add_test(tc, test_easy_parse_chunk_len_matches_chunk_length);
    suite_add_tcase(s, tc);

    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int failures = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failures == 0 ? 0 : 1;
}
