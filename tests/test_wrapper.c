/*
 * test_wrapper.c — format-deniability wrapper smoke + corner-case
 * coverage for the C binding.
 *
 * Mirrors bindings/python/wrapper/tests via the libcheck harness.
 * Each `START_TEST` block stays self-contained — fork-isolated per the
 * existing per-test-binary discipline so libitb global state can be
 * mutated freely (process-wide ITB_SetNonceBits etc. is unaffected
 * here, but the convention is uniform across the suite).
 *
 * Coverage:
 *
 *   1. itb_wrapper_cipher_name interns the canonical short names.
 *   2. itb_wrapper_key_size / itb_wrapper_nonce_size return the
 *      expected per-cipher byte lengths.
 *   3. itb_wrap / itb_unwrap round-trip preserves the blob bytes,
 *      per cipher.
 *   4. itb_wrap / itb_unwrap mismatched-key fails with non-equal blob.
 *   5. itb_wrap_in_place / itb_unwrap_in_place round-trip preserves
 *      the blob bytes, per cipher.
 *   6. itb_wrap_stream_writer + itb_unwrap_stream_reader round-trip,
 *      single-update, per cipher.
 *   7. Streaming round-trip preserves bytes when the writer feeds in
 *      multiple update batches.
 *   8. itb_wrap rejects unknown cipher value with ITB_BAD_INPUT.
 *   9. itb_wrap rejects mismatched key length with ITB_BAD_INPUT.
 *  10. itb_unwrap rejects truncated wire (shorter than nonce) with
 *      ITB_BAD_INPUT.
 *  11. itb_wrap_stream_writer_free is idempotent against double-free
 *      (no crash, no UAF).
 *  12. itb_unwrap_stream_reader_free is idempotent against double-free.
 *  13. Stream reader rejects nonce of wrong length with ITB_BAD_INPUT.
 *  14. itb_wrapper_generate_key returns a buffer of the right length
 *      that can drive a wrap / unwrap round-trip end-to-end.
 *  15. Eitb-style end-to-end: ITB encryptor -> wrap_in_place ->
 *      unwrap_in_place -> ITB decrypt round-trips a small payload.
 */

#include <check.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "itb.h"

/* Test plaintext ~1 KiB — large enough to span multiple AES-CTR
 * blocks / ChaCha20 quarter-round groups while staying small enough
 * for fork()-isolated test harness memory budgets. */
#define BLOB_LEN 1024

static void fill_pattern(uint8_t *buf, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        buf[i] = (uint8_t) ((i * 73u + 19u) & 0xFFu);
    }
}

static const itb_wrapper_cipher_t ALL_CIPHERS[] = {
    ITB_WRAPPER_CIPHER_AES_128_CTR,
    ITB_WRAPPER_CIPHER_CHACHA20,
    ITB_WRAPPER_CIPHER_SIPHASH24,
};

static const size_t ALL_CIPHERS_N = sizeof(ALL_CIPHERS) / sizeof(ALL_CIPHERS[0]);

static const size_t EXPECTED_KEY[]   = { 16, 32, 16 };
static const size_t EXPECTED_NONCE[] = { 16, 12, 16 };

START_TEST(test_wrapper_cipher_name_interned)
{
    ck_assert_str_eq(itb_wrapper_cipher_name(ITB_WRAPPER_CIPHER_AES_128_CTR), "aescmac");
    ck_assert_str_eq(itb_wrapper_cipher_name(ITB_WRAPPER_CIPHER_CHACHA20), "chacha20");
    ck_assert_str_eq(itb_wrapper_cipher_name(ITB_WRAPPER_CIPHER_SIPHASH24), "siphash24");
    ck_assert_ptr_eq(itb_wrapper_cipher_name((itb_wrapper_cipher_t) 99), NULL);
}
END_TEST

START_TEST(test_wrapper_size_accessors)
{
    for (size_t i = 0; i < ALL_CIPHERS_N; i++) {
        size_t k = 0;
        ck_assert_int_eq(itb_wrapper_key_size(ALL_CIPHERS[i], &k), ITB_OK);
        ck_assert_uint_eq(k, EXPECTED_KEY[i]);

        size_t n = 0;
        ck_assert_int_eq(itb_wrapper_nonce_size(ALL_CIPHERS[i], &n), ITB_OK);
        ck_assert_uint_eq(n, EXPECTED_NONCE[i]);
    }
    /* Unknown cipher value rejected. */
    size_t k = 999;
    ck_assert_int_eq(itb_wrapper_key_size((itb_wrapper_cipher_t) 99, &k), ITB_BAD_INPUT);
    ck_assert_uint_eq(k, 0);
    /* NULL out_size rejected. */
    ck_assert_int_eq(itb_wrapper_key_size(ITB_WRAPPER_CIPHER_AES_128_CTR, NULL),
                     ITB_BAD_INPUT);
}
END_TEST

START_TEST(test_wrap_unwrap_roundtrip_per_cipher)
{
    uint8_t blob[BLOB_LEN];
    fill_pattern(blob, BLOB_LEN);

    for (size_t i = 0; i < ALL_CIPHERS_N; i++) {
        itb_wrapper_cipher_t cipher = ALL_CIPHERS[i];

        uint8_t *key = NULL;
        size_t key_len = 0;
        ck_assert_int_eq(itb_wrapper_generate_key(cipher, &key, &key_len), ITB_OK);
        ck_assert_uint_eq(key_len, EXPECTED_KEY[i]);

        uint8_t *wire = NULL;
        size_t wire_len = 0;
        ck_assert_int_eq(itb_wrap(cipher, key, key_len, blob, BLOB_LEN,
                                  &wire, &wire_len), ITB_OK);
        ck_assert_uint_eq(wire_len, EXPECTED_NONCE[i] + BLOB_LEN);

        /* Wire body must differ from the input (XOR under a CSPRNG-
         * drawn nonce; collision odds are negligible). */
        ck_assert_int_ne(memcmp(wire + EXPECTED_NONCE[i], blob, BLOB_LEN), 0);

        uint8_t *recovered = NULL;
        size_t recovered_len = 0;
        ck_assert_int_eq(itb_unwrap(cipher, key, key_len, wire, wire_len,
                                    &recovered, &recovered_len), ITB_OK);
        ck_assert_uint_eq(recovered_len, BLOB_LEN);
        ck_assert_mem_eq(recovered, blob, BLOB_LEN);

        itb_buffer_free(wire);
        itb_buffer_free(recovered);
        itb_buffer_free(key);
    }
}
END_TEST

START_TEST(test_wrap_unwrap_wrong_key_recovers_garbage)
{
    uint8_t blob[BLOB_LEN];
    fill_pattern(blob, BLOB_LEN);

    itb_wrapper_cipher_t cipher = ITB_WRAPPER_CIPHER_AES_128_CTR;

    uint8_t *key1 = NULL, *key2 = NULL;
    size_t k1 = 0, k2 = 0;
    ck_assert_int_eq(itb_wrapper_generate_key(cipher, &key1, &k1), ITB_OK);
    ck_assert_int_eq(itb_wrapper_generate_key(cipher, &key2, &k2), ITB_OK);

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    ck_assert_int_eq(itb_wrap(cipher, key1, k1, blob, BLOB_LEN, &wire, &wire_len),
                     ITB_OK);

    uint8_t *recovered = NULL;
    size_t rl = 0;
    /* Different key -> Unwrap succeeds (XOR is unconditional) but the
     * recovered bytes are garbage. */
    ck_assert_int_eq(itb_unwrap(cipher, key2, k2, wire, wire_len,
                                &recovered, &rl), ITB_OK);
    ck_assert_uint_eq(rl, BLOB_LEN);
    ck_assert_int_ne(memcmp(recovered, blob, BLOB_LEN), 0);

    itb_buffer_free(wire);
    itb_buffer_free(recovered);
    itb_buffer_free(key1);
    itb_buffer_free(key2);
}
END_TEST

START_TEST(test_wrap_in_place_roundtrip_per_cipher)
{
    uint8_t blob_orig[BLOB_LEN];
    fill_pattern(blob_orig, BLOB_LEN);

    for (size_t i = 0; i < ALL_CIPHERS_N; i++) {
        itb_wrapper_cipher_t cipher = ALL_CIPHERS[i];
        size_t nlen = EXPECTED_NONCE[i];

        uint8_t *key = NULL;
        size_t key_len = 0;
        ck_assert_int_eq(itb_wrapper_generate_key(cipher, &key, &key_len), ITB_OK);

        uint8_t blob[BLOB_LEN];
        memcpy(blob, blob_orig, BLOB_LEN);
        uint8_t nonce[16] = {0};

        ck_assert_int_eq(
            itb_wrap_in_place(cipher, key, key_len, blob, BLOB_LEN, nonce, sizeof(nonce)),
            ITB_OK);
        /* In-place mutated. */
        ck_assert_int_ne(memcmp(blob, blob_orig, BLOB_LEN), 0);

        /* Compose wire = nonce || blob, then unwrap-in-place. */
        size_t wire_len = nlen + BLOB_LEN;
        uint8_t *wire = (uint8_t *) malloc(wire_len);
        ck_assert_ptr_nonnull(wire);
        memcpy(wire, nonce, nlen);
        memcpy(wire + nlen, blob, BLOB_LEN);

        ck_assert_int_eq(
            itb_unwrap_in_place(cipher, key, key_len, wire, wire_len),
            ITB_OK);
        ck_assert_mem_eq(wire + nlen, blob_orig, BLOB_LEN);

        free(wire);
        itb_buffer_free(key);
    }
}
END_TEST

START_TEST(test_stream_writer_reader_roundtrip_per_cipher)
{
    uint8_t blob[BLOB_LEN];
    fill_pattern(blob, BLOB_LEN);

    for (size_t i = 0; i < ALL_CIPHERS_N; i++) {
        itb_wrapper_cipher_t cipher = ALL_CIPHERS[i];
        size_t nlen = EXPECTED_NONCE[i];

        uint8_t *key = NULL;
        size_t key_len = 0;
        ck_assert_int_eq(itb_wrapper_generate_key(cipher, &key, &key_len), ITB_OK);

        uint8_t nonce[16] = {0};
        itb_wrap_stream_writer_t *w = NULL;
        ck_assert_int_eq(
            itb_wrap_stream_writer_new(cipher, key, key_len, nonce, sizeof(nonce), &w),
            ITB_OK);
        ck_assert_ptr_nonnull(w);

        uint8_t encrypted[BLOB_LEN];
        ck_assert_int_eq(
            itb_wrap_stream_writer_update(w, blob, BLOB_LEN, encrypted, BLOB_LEN),
            ITB_OK);
        /* Encrypted bytes differ from input. */
        ck_assert_int_ne(memcmp(encrypted, blob, BLOB_LEN), 0);

        itb_unwrap_stream_reader_t *r = NULL;
        ck_assert_int_eq(
            itb_unwrap_stream_reader_new(cipher, key, key_len, nonce, nlen, &r),
            ITB_OK);
        ck_assert_ptr_nonnull(r);

        uint8_t recovered[BLOB_LEN];
        ck_assert_int_eq(
            itb_unwrap_stream_reader_update(r, encrypted, BLOB_LEN, recovered, BLOB_LEN),
            ITB_OK);
        ck_assert_mem_eq(recovered, blob, BLOB_LEN);

        itb_wrap_stream_writer_free(w);
        itb_unwrap_stream_reader_free(r);
        itb_buffer_free(key);
    }
}
END_TEST

START_TEST(test_stream_writer_reader_multi_update)
{
    /* Drive the writer with three updates of unequal size; reader
     * consumes the same boundary layout. The keystream counter is
     * monotonic across calls, so a different boundary on the reader
     * side must still recover the original bytes. */
    uint8_t blob[BLOB_LEN];
    fill_pattern(blob, BLOB_LEN);

    itb_wrapper_cipher_t cipher = ITB_WRAPPER_CIPHER_CHACHA20;

    uint8_t *key = NULL;
    size_t key_len = 0;
    ck_assert_int_eq(itb_wrapper_generate_key(cipher, &key, &key_len), ITB_OK);

    uint8_t nonce[16] = {0};
    itb_wrap_stream_writer_t *w = NULL;
    ck_assert_int_eq(
        itb_wrap_stream_writer_new(cipher, key, key_len, nonce, sizeof(nonce), &w),
        ITB_OK);

    uint8_t encrypted[BLOB_LEN];
    /* Three batches: 100 / 400 / 524 = 1024 = BLOB_LEN. */
    ck_assert_int_eq(
        itb_wrap_stream_writer_update(w, blob, 100, encrypted, 100), ITB_OK);
    ck_assert_int_eq(
        itb_wrap_stream_writer_update(w, blob + 100, 400, encrypted + 100, 400), ITB_OK);
    ck_assert_int_eq(
        itb_wrap_stream_writer_update(w, blob + 500, 524, encrypted + 500, 524), ITB_OK);

    itb_unwrap_stream_reader_t *r = NULL;
    ck_assert_int_eq(
        itb_unwrap_stream_reader_new(cipher, key, key_len, nonce, 12, &r), ITB_OK);

    uint8_t recovered[BLOB_LEN];
    /* Reader consumes with a different split: 256 / 256 / 512. */
    ck_assert_int_eq(
        itb_unwrap_stream_reader_update(r, encrypted, 256, recovered, 256), ITB_OK);
    ck_assert_int_eq(
        itb_unwrap_stream_reader_update(r, encrypted + 256, 256, recovered + 256, 256), ITB_OK);
    ck_assert_int_eq(
        itb_unwrap_stream_reader_update(r, encrypted + 512, 512, recovered + 512, 512), ITB_OK);

    ck_assert_mem_eq(recovered, blob, BLOB_LEN);

    itb_wrap_stream_writer_free(w);
    itb_unwrap_stream_reader_free(r);
    itb_buffer_free(key);
}
END_TEST

START_TEST(test_wrap_unknown_cipher_rejected)
{
    uint8_t key[32] = {0};
    uint8_t blob[16] = {0};
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    ck_assert_int_eq(
        itb_wrap((itb_wrapper_cipher_t) 99, key, 16, blob, 16, &wire, &wire_len),
        ITB_BAD_INPUT);
    ck_assert_ptr_eq(wire, NULL);
}
END_TEST

START_TEST(test_wrap_mismatched_key_length_rejected)
{
    uint8_t key[15] = {0};   /* AES wants 16 — short by 1. */
    uint8_t blob[16] = {0};
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    ck_assert_int_eq(
        itb_wrap(ITB_WRAPPER_CIPHER_AES_128_CTR, key, 15, blob, 16, &wire, &wire_len),
        ITB_BAD_INPUT);
    ck_assert_ptr_eq(wire, NULL);
}
END_TEST

START_TEST(test_unwrap_truncated_wire_rejected)
{
    /* AES nonce is 16 bytes; pass 8 bytes only. */
    uint8_t key[16] = {0};
    uint8_t wire[8] = {0};
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    ck_assert_int_eq(
        itb_unwrap(ITB_WRAPPER_CIPHER_AES_128_CTR, key, 16, wire, 8, &blob, &blob_len),
        ITB_BAD_INPUT);
    ck_assert_ptr_eq(blob, NULL);
}
END_TEST

START_TEST(test_stream_writer_double_free_idempotent)
{
    uint8_t key[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t nonce[16] = {0};
    itb_wrap_stream_writer_t *w = NULL;
    ck_assert_int_eq(
        itb_wrap_stream_writer_new(ITB_WRAPPER_CIPHER_AES_128_CTR,
                                   key, 16, nonce, sizeof(nonce), &w),
        ITB_OK);
    ck_assert_ptr_nonnull(w);
    /* Free once — releases libitb handle, deallocates wrapper. */
    itb_wrap_stream_writer_free(w);
    /* Free NULL — no-op. */
    itb_wrap_stream_writer_free(NULL);
}
END_TEST

START_TEST(test_stream_reader_double_free_idempotent)
{
    uint8_t key[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t nonce[16] = {0};
    itb_unwrap_stream_reader_t *r = NULL;
    ck_assert_int_eq(
        itb_unwrap_stream_reader_new(ITB_WRAPPER_CIPHER_AES_128_CTR,
                                     key, 16, nonce, 16, &r),
        ITB_OK);
    ck_assert_ptr_nonnull(r);
    itb_unwrap_stream_reader_free(r);
    itb_unwrap_stream_reader_free(NULL);
}
END_TEST

START_TEST(test_stream_reader_wrong_nonce_length_rejected)
{
    uint8_t key[16] = {0};
    uint8_t nonce_short[8] = {0};
    itb_unwrap_stream_reader_t *r = NULL;
    ck_assert_int_eq(
        itb_unwrap_stream_reader_new(ITB_WRAPPER_CIPHER_AES_128_CTR,
                                     key, 16, nonce_short, 8, &r),
        ITB_BAD_INPUT);
    ck_assert_ptr_eq(r, NULL);
}
END_TEST

START_TEST(test_generate_key_drives_full_roundtrip)
{
    uint8_t blob[BLOB_LEN];
    fill_pattern(blob, BLOB_LEN);

    uint8_t *key = NULL;
    size_t key_len = 0;
    ck_assert_int_eq(
        itb_wrapper_generate_key(ITB_WRAPPER_CIPHER_SIPHASH24, &key, &key_len), ITB_OK);
    ck_assert_uint_eq(key_len, 16);

    /* Different keys across two calls — sanity check on the CSPRNG.  */
    uint8_t *key2 = NULL;
    size_t kl2 = 0;
    ck_assert_int_eq(
        itb_wrapper_generate_key(ITB_WRAPPER_CIPHER_SIPHASH24, &key2, &kl2), ITB_OK);
    ck_assert_int_ne(memcmp(key, key2, 16), 0);
    itb_buffer_free(key2);

    uint8_t *wire = NULL; size_t wl = 0;
    ck_assert_int_eq(
        itb_wrap(ITB_WRAPPER_CIPHER_SIPHASH24, key, key_len, blob, BLOB_LEN,
                 &wire, &wl), ITB_OK);
    uint8_t *recovered = NULL; size_t rl = 0;
    ck_assert_int_eq(
        itb_unwrap(ITB_WRAPPER_CIPHER_SIPHASH24, key, key_len, wire, wl,
                   &recovered, &rl), ITB_OK);
    ck_assert_mem_eq(recovered, blob, BLOB_LEN);

    itb_buffer_free(wire);
    itb_buffer_free(recovered);
    itb_buffer_free(key);
}
END_TEST

/* itb_wrapper_derive_key: deterministic key derivation from a 32-byte
 * master (a stand-in for an ML-KEM shared secret; the binding ships no
 * KEM, so a 32-byte CSPRNG draw is used). Per cipher: the derived key
 * length matches itb_wrapper_key_size, two derivations from the same
 * (cipher, master) agree, and the derived key drives a full
 * wrap/unwrap round-trip. */
START_TEST(test_derive_key_deterministic_and_roundtrips)
{
    uint8_t blob[BLOB_LEN];
    fill_pattern(blob, BLOB_LEN);

    /* 32 random bytes as the master secret. */
    uint8_t master[32];
    FILE *fp = fopen("/dev/urandom", "rb");
    ck_assert_ptr_nonnull(fp);
    ck_assert_uint_eq(fread(master, 1, sizeof(master), fp), sizeof(master));
    fclose(fp);

    for (size_t i = 0; i < ALL_CIPHERS_N; i++) {
        itb_wrapper_cipher_t cipher = ALL_CIPHERS[i];

        uint8_t *key1 = NULL;
        size_t key1_len = 0;
        ck_assert_int_eq(
            itb_wrapper_derive_key(cipher, master, sizeof(master),
                                   &key1, &key1_len), ITB_OK);
        ck_assert_uint_eq(key1_len, EXPECTED_KEY[i]);

        /* Determinism: same (cipher, master) yields the same key. */
        uint8_t *key2 = NULL;
        size_t key2_len = 0;
        ck_assert_int_eq(
            itb_wrapper_derive_key(cipher, master, sizeof(master),
                                   &key2, &key2_len), ITB_OK);
        ck_assert_uint_eq(key2_len, key1_len);
        ck_assert_mem_eq(key1, key2, key1_len);
        itb_buffer_free(key2);

        /* The derived key round-trips through wrap/unwrap. */
        uint8_t *wire = NULL;
        size_t wire_len = 0;
        ck_assert_int_eq(itb_wrap(cipher, key1, key1_len, blob, BLOB_LEN,
                                  &wire, &wire_len), ITB_OK);
        uint8_t *recovered = NULL;
        size_t recovered_len = 0;
        ck_assert_int_eq(itb_unwrap(cipher, key1, key1_len, wire, wire_len,
                                    &recovered, &recovered_len), ITB_OK);
        ck_assert_uint_eq(recovered_len, BLOB_LEN);
        ck_assert_mem_eq(recovered, blob, BLOB_LEN);

        itb_buffer_free(wire);
        itb_buffer_free(recovered);
        itb_buffer_free(key1);
    }
}
END_TEST

START_TEST(test_eitb_style_end_to_end_message_easy_nomac)
{
    /* End-to-end smoke matching one cell of the eitb matrix:
     * Easy.encrypt(plaintext) -> wrap_in_place -> unwrap_in_place ->
     * Easy.decrypt(recovered). */
    static const uint8_t PT[] =
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do "
        "eiusmod tempor incididunt ut labore et dolore magna aliqua.";
    const size_t PT_LEN = sizeof(PT) - 1;

    itb_encryptor_t *enc = NULL;
    /* Easy Mode without MAC — pass empty mac_name. */
    ck_assert_int_eq(itb_encryptor_new("areion512", 1024, "", 1, &enc), ITB_OK);
    ck_assert_ptr_nonnull(enc);

    uint8_t *ct = NULL; size_t ct_len = 0;
    ck_assert_int_eq(itb_encryptor_encrypt(enc, PT, PT_LEN, &ct, &ct_len), ITB_OK);

    /* Wrap in place. */
    itb_wrapper_cipher_t cipher = ITB_WRAPPER_CIPHER_AES_128_CTR;
    uint8_t *key = NULL; size_t key_len = 0;
    ck_assert_int_eq(itb_wrapper_generate_key(cipher, &key, &key_len), ITB_OK);

    uint8_t nonce[16] = {0};
    ck_assert_int_eq(
        itb_wrap_in_place(cipher, key, key_len, ct, ct_len, nonce, sizeof(nonce)),
        ITB_OK);

    /* Compose wire = nonce || ct (both heap-owned). */
    size_t wire_len = 16 + ct_len;
    uint8_t *wire = (uint8_t *) malloc(wire_len);
    ck_assert_ptr_nonnull(wire);
    memcpy(wire, nonce, 16);
    memcpy(wire + 16, ct, ct_len);

    /* Unwrap in place. */
    ck_assert_int_eq(
        itb_unwrap_in_place(cipher, key, key_len, wire, wire_len), ITB_OK);

    /* Decrypt. */
    uint8_t *pt = NULL; size_t pt_len = 0;
    ck_assert_int_eq(
        itb_encryptor_decrypt(enc, wire + 16, ct_len, &pt, &pt_len), ITB_OK);
    ck_assert_uint_eq(pt_len, PT_LEN);
    ck_assert_mem_eq(pt, PT, PT_LEN);

    itb_buffer_free(pt);
    free(wire);
    itb_buffer_free(ct);
    itb_buffer_free(key);
    itb_encryptor_free(enc);
}
END_TEST

int main(void)
{
    Suite *s = suite_create("wrapper");
    TCase *tc = tcase_create("core");
    tcase_set_timeout(tc, 60);
    tcase_add_test(tc, test_wrapper_cipher_name_interned);
    tcase_add_test(tc, test_wrapper_size_accessors);
    tcase_add_test(tc, test_wrap_unwrap_roundtrip_per_cipher);
    tcase_add_test(tc, test_wrap_unwrap_wrong_key_recovers_garbage);
    tcase_add_test(tc, test_wrap_in_place_roundtrip_per_cipher);
    tcase_add_test(tc, test_stream_writer_reader_roundtrip_per_cipher);
    tcase_add_test(tc, test_stream_writer_reader_multi_update);
    tcase_add_test(tc, test_wrap_unknown_cipher_rejected);
    tcase_add_test(tc, test_wrap_mismatched_key_length_rejected);
    tcase_add_test(tc, test_unwrap_truncated_wire_rejected);
    tcase_add_test(tc, test_stream_writer_double_free_idempotent);
    tcase_add_test(tc, test_stream_reader_double_free_idempotent);
    tcase_add_test(tc, test_stream_reader_wrong_nonce_length_rejected);
    tcase_add_test(tc, test_generate_key_drives_full_roundtrip);
    tcase_add_test(tc, test_derive_key_deterministic_and_roundtrips);
    tcase_add_test(tc, test_eitb_style_end_to_end_message_easy_nomac);
    suite_add_tcase(s, tc);

    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int failures = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failures == 0 ? 0 : 1;
}
