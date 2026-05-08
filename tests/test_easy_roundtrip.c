/*
 * test_easy_roundtrip.c — end-to-end coverage for the high-level
 * Encryptor surface.
 *
 * Mirrors bindings/rust/tests/test_easy_roundtrip.rs one-to-one.
 * Lifecycle tests (close / free / handle invalidation), structural
 * validation (bad primitive / MAC / key_bits / mode), full-matrix
 * round-trips for both Single and Triple Ouroboros, and per-instance
 * configuration setters that mutate only the local Config copy without
 * touching libitb's process-global state.
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

static const int CANDIDATE_KB[] = {512, 1024, 2048};
#define CANDIDATE_KB_COUNT (sizeof(CANDIDATE_KB) / sizeof(CANDIDATE_KB[0]))

static uint8_t *token_bytes(size_t n) {
    static uint64_t ctr = 0xF00DCAFEBAADF00DULL;
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

/* ─── Lifecycle ─────────────────────────────────────────────────── */

START_TEST(test_easy_roundtrip_new_and_free)
{
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &enc), ITB_OK);
    ck_assert_ptr_nonnull(enc);

    char buf[64]; size_t blen = 0;
    ck_assert_int_eq(itb_encryptor_primitive(enc, buf, sizeof(buf), &blen), ITB_OK);
    ck_assert_str_eq(buf, "blake3");
    int kb = 0;
    ck_assert_int_eq(itb_encryptor_key_bits(enc, &kb), ITB_OK);
    ck_assert_int_eq(kb, 1024);
    int mode = 0;
    ck_assert_int_eq(itb_encryptor_mode(enc, &mode), ITB_OK);
    ck_assert_int_eq(mode, 1);
    ck_assert_int_eq(itb_encryptor_mac_name(enc, buf, sizeof(buf), &blen), ITB_OK);
    ck_assert_str_eq(buf, "kmac256");

    itb_encryptor_free(enc);
}
END_TEST

START_TEST(test_easy_roundtrip_free_releases_handle)
{
    /* C analogue of Rust's Drop test — itb_encryptor_free releases the
     * libitb-side handle when the wrapper goes out of scope. */
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new("areion256", 1024, "kmac256", 1, &enc), ITB_OK);
    ck_assert_ptr_nonnull(enc);
    itb_encryptor_free(enc);
}
END_TEST

START_TEST(test_easy_roundtrip_double_free_idempotent)
{
    /* close-then-free mirrors the Rust free()-twice-no-raise contract.
     * itb_encryptor_free is documented as idempotent against a
     * previously-closed encryptor, and accepts NULL as a no-op. */
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &enc), ITB_OK);
    ck_assert_int_eq(itb_encryptor_close(enc), ITB_OK);
    itb_encryptor_free(enc);
    /* NULL is also accepted as a no-op. */
    itb_encryptor_free(NULL);
}
END_TEST

START_TEST(test_easy_roundtrip_close_then_method_raises)
{
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &enc), ITB_OK);
    ck_assert_int_eq(itb_encryptor_close(enc), ITB_OK);

    static const uint8_t plaintext[] = "after close";
    uint8_t *out = NULL; size_t out_len = 0;
    ck_assert_int_eq(itb_encryptor_encrypt(enc, plaintext, sizeof(plaintext) - 1,
                                           &out, &out_len), ITB_EASY_CLOSED);
    ck_assert_ptr_null(out);
    itb_encryptor_free(enc);
}
END_TEST

START_TEST(test_easy_roundtrip_defaults)
{
    /* NULL primitive / 0 key_bits / NULL mac select package defaults:
     * areion512 / 1024 / hmac-blake3. */
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new(NULL, 0, NULL, 1, &enc), ITB_OK);

    char buf[64]; size_t blen = 0;
    ck_assert_int_eq(itb_encryptor_primitive(enc, buf, sizeof(buf), &blen), ITB_OK);
    ck_assert_str_eq(buf, "areion512");
    int kb = 0;
    ck_assert_int_eq(itb_encryptor_key_bits(enc, &kb), ITB_OK);
    ck_assert_int_eq(kb, 1024);
    int mode = 0;
    ck_assert_int_eq(itb_encryptor_mode(enc, &mode), ITB_OK);
    ck_assert_int_eq(mode, 1);
    ck_assert_int_eq(itb_encryptor_mac_name(enc, buf, sizeof(buf), &blen), ITB_OK);
    ck_assert_str_eq(buf, "hmac-blake3");

    itb_encryptor_free(enc);
}
END_TEST

START_TEST(test_easy_roundtrip_bad_primitive)
{
    itb_encryptor_t *enc = (itb_encryptor_t *)0x1;
    ck_assert_int_ne(itb_encryptor_new("nonsense-hash", 1024, "kmac256", 1, &enc), ITB_OK);
    ck_assert_ptr_null(enc);
}
END_TEST

START_TEST(test_easy_roundtrip_bad_mac)
{
    itb_encryptor_t *enc = (itb_encryptor_t *)0x1;
    ck_assert_int_ne(itb_encryptor_new("blake3", 1024, "nonsense-mac", 1, &enc), ITB_OK);
    ck_assert_ptr_null(enc);
}
END_TEST

START_TEST(test_easy_roundtrip_bad_key_bits)
{
    static const int BAD[] = {256, 511, 999, 2049};
    for (size_t i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++) {
        itb_encryptor_t *enc = (itb_encryptor_t *)0x1;
        itb_status_t rc = itb_encryptor_new("blake3", BAD[i], "kmac256", 1, &enc);
        ck_assert_int_ne(rc, ITB_OK);
        ck_assert_ptr_null(enc);
    }
}
END_TEST

START_TEST(test_easy_roundtrip_bad_mode)
{
    itb_encryptor_t *enc = (itb_encryptor_t *)0x1;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 2, &enc), ITB_BAD_INPUT);
    ck_assert_ptr_null(enc);
}
END_TEST

/* ─── Roundtrip Single ─────────────────────────────────────────── */

START_TEST(test_easy_roundtrip_all_hashes_all_widths_single)
{
    size_t pt_len = 4096;
    uint8_t *plaintext = token_bytes(pt_len);

    for (size_t hi = 0; hi < CANONICAL_HASHES_COUNT; hi++) {
        const char *name = CANONICAL_HASHES[hi].name;
        int width = CANONICAL_HASHES[hi].width;
        for (size_t ki = 0; ki < CANDIDATE_KB_COUNT; ki++) {
            int kb = CANDIDATE_KB[ki];
            if (kb % width != 0) continue;

            itb_encryptor_t *enc = NULL;
            ck_assert_int_eq(itb_encryptor_new(name, kb, "kmac256", 1, &enc), ITB_OK);

            uint8_t *ct = NULL; size_t ct_len = 0;
            ck_assert_int_eq(itb_encryptor_encrypt(enc, plaintext, pt_len, &ct, &ct_len),
                             ITB_OK);
            ck_assert_uint_gt(ct_len, pt_len);
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

START_TEST(test_easy_roundtrip_all_hashes_all_widths_single_auth)
{
    size_t pt_len = 4096;
    uint8_t *plaintext = token_bytes(pt_len);

    for (size_t hi = 0; hi < CANONICAL_HASHES_COUNT; hi++) {
        const char *name = CANONICAL_HASHES[hi].name;
        int width = CANONICAL_HASHES[hi].width;
        for (size_t ki = 0; ki < CANDIDATE_KB_COUNT; ki++) {
            int kb = CANDIDATE_KB[ki];
            if (kb % width != 0) continue;

            itb_encryptor_t *enc = NULL;
            ck_assert_int_eq(itb_encryptor_new(name, kb, "kmac256", 1, &enc), ITB_OK);

            uint8_t *ct = NULL; size_t ct_len = 0;
            ck_assert_int_eq(itb_encryptor_encrypt_auth(enc, plaintext, pt_len,
                                                        &ct, &ct_len), ITB_OK);
            uint8_t *pt = NULL; size_t pt_out_len = 0;
            ck_assert_int_eq(itb_encryptor_decrypt_auth(enc, ct, ct_len,
                                                        &pt, &pt_out_len), ITB_OK);
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

START_TEST(test_easy_roundtrip_slice_input_roundtrip)
{
    /* C analogue of Rust's slice / bytearray roundtrip — confirm the
     * cipher accepts an arbitrary const-byte buffer pair. */
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &enc), ITB_OK);
    static const uint8_t payload[] = "hello bytearray";
    size_t pt_len = sizeof(payload) - 1;

    uint8_t *ct = NULL; size_t ct_len = 0;
    ck_assert_int_eq(itb_encryptor_encrypt(enc, payload, pt_len, &ct, &ct_len), ITB_OK);
    uint8_t *pt = NULL; size_t pt_out_len = 0;
    ck_assert_int_eq(itb_encryptor_decrypt(enc, ct, ct_len, &pt, &pt_out_len), ITB_OK);
    ck_assert_uint_eq(pt_out_len, pt_len);
    ck_assert_mem_eq(pt, payload, pt_len);

    itb_buffer_free(ct);
    itb_buffer_free(pt);
    itb_encryptor_free(enc);
}
END_TEST

/* ─── Roundtrip Triple ─────────────────────────────────────────── */

START_TEST(test_easy_roundtrip_all_hashes_all_widths_triple)
{
    size_t pt_len = 4096;
    uint8_t *plaintext = token_bytes(pt_len);

    for (size_t hi = 0; hi < CANONICAL_HASHES_COUNT; hi++) {
        const char *name = CANONICAL_HASHES[hi].name;
        int width = CANONICAL_HASHES[hi].width;
        for (size_t ki = 0; ki < CANDIDATE_KB_COUNT; ki++) {
            int kb = CANDIDATE_KB[ki];
            if (kb % width != 0) continue;

            itb_encryptor_t *enc = NULL;
            ck_assert_int_eq(itb_encryptor_new(name, kb, "kmac256", 3, &enc), ITB_OK);

            uint8_t *ct = NULL; size_t ct_len = 0;
            ck_assert_int_eq(itb_encryptor_encrypt(enc, plaintext, pt_len, &ct, &ct_len),
                             ITB_OK);
            ck_assert_uint_gt(ct_len, pt_len);
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

START_TEST(test_easy_roundtrip_all_hashes_all_widths_triple_auth)
{
    size_t pt_len = 4096;
    uint8_t *plaintext = token_bytes(pt_len);

    for (size_t hi = 0; hi < CANONICAL_HASHES_COUNT; hi++) {
        const char *name = CANONICAL_HASHES[hi].name;
        int width = CANONICAL_HASHES[hi].width;
        for (size_t ki = 0; ki < CANDIDATE_KB_COUNT; ki++) {
            int kb = CANDIDATE_KB[ki];
            if (kb % width != 0) continue;

            itb_encryptor_t *enc = NULL;
            ck_assert_int_eq(itb_encryptor_new(name, kb, "kmac256", 3, &enc), ITB_OK);

            uint8_t *ct = NULL; size_t ct_len = 0;
            ck_assert_int_eq(itb_encryptor_encrypt_auth(enc, plaintext, pt_len,
                                                        &ct, &ct_len), ITB_OK);
            uint8_t *pt = NULL; size_t pt_out_len = 0;
            ck_assert_int_eq(itb_encryptor_decrypt_auth(enc, ct, ct_len,
                                                        &pt, &pt_out_len), ITB_OK);
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

START_TEST(test_easy_roundtrip_seed_count_reflects_mode)
{
    itb_encryptor_t *enc1 = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &enc1), ITB_OK);
    int sc = 0;
    ck_assert_int_eq(itb_encryptor_seed_count(enc1, &sc), ITB_OK);
    ck_assert_int_eq(sc, 3);
    itb_encryptor_free(enc1);

    itb_encryptor_t *enc3 = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 3, &enc3), ITB_OK);
    ck_assert_int_eq(itb_encryptor_seed_count(enc3, &sc), ITB_OK);
    ck_assert_int_eq(sc, 7);
    itb_encryptor_free(enc3);
}
END_TEST

/* ─── Per-instance configuration ───────────────────────────────── */

START_TEST(test_easy_roundtrip_set_bit_soup)
{
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &enc), ITB_OK);
    ck_assert_int_eq(itb_encryptor_set_bit_soup(enc, 1), ITB_OK);

    static const uint8_t plaintext[] = "bit-soup payload";
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

START_TEST(test_easy_roundtrip_set_lock_soup_couples_bit_soup)
{
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &enc), ITB_OK);
    ck_assert_int_eq(itb_encryptor_set_lock_soup(enc, 1), ITB_OK);

    static const uint8_t plaintext[] = "lock-soup payload";
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

START_TEST(test_easy_roundtrip_set_lock_seed_grows_seed_count)
{
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &enc), ITB_OK);
    int sc = 0;
    ck_assert_int_eq(itb_encryptor_seed_count(enc, &sc), ITB_OK);
    ck_assert_int_eq(sc, 3);
    ck_assert_int_eq(itb_encryptor_set_lock_seed(enc, 1), ITB_OK);
    ck_assert_int_eq(itb_encryptor_seed_count(enc, &sc), ITB_OK);
    ck_assert_int_eq(sc, 4);

    static const uint8_t plaintext[] = "lockseed payload";
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

START_TEST(test_easy_roundtrip_set_lock_seed_after_encrypt_rejected)
{
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &enc), ITB_OK);
    static const uint8_t first[] = "first";
    uint8_t *ct = NULL; size_t ct_len = 0;
    ck_assert_int_eq(itb_encryptor_encrypt(enc, first, sizeof(first) - 1,
                                           &ct, &ct_len), ITB_OK);
    ck_assert_int_eq(itb_encryptor_set_lock_seed(enc, 1),
                     ITB_EASY_LOCKSEED_AFTER_ENCRYPT);
    itb_buffer_free(ct);
    itb_encryptor_free(enc);
}
END_TEST

START_TEST(test_easy_roundtrip_set_nonce_bits_validation)
{
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &enc), ITB_OK);
    static const int VALID[] = {128, 256, 512};
    for (size_t i = 0; i < sizeof(VALID) / sizeof(VALID[0]); i++) {
        ck_assert_int_eq(itb_encryptor_set_nonce_bits(enc, VALID[i]), ITB_OK);
    }
    static const int BAD[] = {0, 1, 192, 1024};
    for (size_t i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++) {
        ck_assert_int_eq(itb_encryptor_set_nonce_bits(enc, BAD[i]), ITB_BAD_INPUT);
    }
    itb_encryptor_free(enc);
}
END_TEST

START_TEST(test_easy_roundtrip_set_barrier_fill_validation)
{
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &enc), ITB_OK);
    static const int VALID[] = {1, 2, 4, 8, 16, 32};
    for (size_t i = 0; i < sizeof(VALID) / sizeof(VALID[0]); i++) {
        ck_assert_int_eq(itb_encryptor_set_barrier_fill(enc, VALID[i]), ITB_OK);
    }
    static const int BAD[] = {0, 3, 5, 7, 64};
    for (size_t i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++) {
        ck_assert_int_eq(itb_encryptor_set_barrier_fill(enc, BAD[i]), ITB_BAD_INPUT);
    }
    itb_encryptor_free(enc);
}
END_TEST

START_TEST(test_easy_roundtrip_set_chunk_size_accepted)
{
    itb_encryptor_t *enc = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &enc), ITB_OK);
    ck_assert_int_eq(itb_encryptor_set_chunk_size(enc, 1024), ITB_OK);
    ck_assert_int_eq(itb_encryptor_set_chunk_size(enc, 0), ITB_OK);
    itb_encryptor_free(enc);
}
END_TEST

START_TEST(test_easy_roundtrip_two_encryptors_isolated)
{
    /* Setting LockSoup on one encryptor must not bleed into another;
     * per-instance Config snapshots are independent. */
    itb_encryptor_t *a = NULL;
    itb_encryptor_t *b = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &a), ITB_OK);
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 1, &b), ITB_OK);
    ck_assert_int_eq(itb_encryptor_set_lock_soup(a, 1), ITB_OK);

    static const uint8_t pa[] = "a";
    static const uint8_t pb[] = "b";
    uint8_t *ct_a = NULL; size_t ct_a_len = 0;
    ck_assert_int_eq(itb_encryptor_encrypt(a, pa, 1, &ct_a, &ct_a_len), ITB_OK);
    uint8_t *pt_a = NULL; size_t pt_a_len = 0;
    ck_assert_int_eq(itb_encryptor_decrypt(a, ct_a, ct_a_len, &pt_a, &pt_a_len), ITB_OK);
    ck_assert_uint_eq(pt_a_len, 1);
    ck_assert_int_eq(pt_a[0], 'a');

    uint8_t *ct_b = NULL; size_t ct_b_len = 0;
    ck_assert_int_eq(itb_encryptor_encrypt(b, pb, 1, &ct_b, &ct_b_len), ITB_OK);
    uint8_t *pt_b = NULL; size_t pt_b_len = 0;
    ck_assert_int_eq(itb_encryptor_decrypt(b, ct_b, ct_b_len, &pt_b, &pt_b_len), ITB_OK);
    ck_assert_uint_eq(pt_b_len, 1);
    ck_assert_int_eq(pt_b[0], 'b');

    itb_buffer_free(ct_a);
    itb_buffer_free(pt_a);
    itb_buffer_free(ct_b);
    itb_buffer_free(pt_b);
    itb_encryptor_free(a);
    itb_encryptor_free(b);
}
END_TEST

int main(void)
{
    Suite *s = suite_create("easy_roundtrip");
    TCase *tc = tcase_create("core");
    tcase_set_timeout(tc, 300);
    tcase_add_test(tc, test_easy_roundtrip_new_and_free);
    tcase_add_test(tc, test_easy_roundtrip_free_releases_handle);
    tcase_add_test(tc, test_easy_roundtrip_double_free_idempotent);
    tcase_add_test(tc, test_easy_roundtrip_close_then_method_raises);
    tcase_add_test(tc, test_easy_roundtrip_defaults);
    tcase_add_test(tc, test_easy_roundtrip_bad_primitive);
    tcase_add_test(tc, test_easy_roundtrip_bad_mac);
    tcase_add_test(tc, test_easy_roundtrip_bad_key_bits);
    tcase_add_test(tc, test_easy_roundtrip_bad_mode);
    tcase_add_test(tc, test_easy_roundtrip_all_hashes_all_widths_single);
    tcase_add_test(tc, test_easy_roundtrip_all_hashes_all_widths_single_auth);
    tcase_add_test(tc, test_easy_roundtrip_slice_input_roundtrip);
    tcase_add_test(tc, test_easy_roundtrip_all_hashes_all_widths_triple);
    tcase_add_test(tc, test_easy_roundtrip_all_hashes_all_widths_triple_auth);
    tcase_add_test(tc, test_easy_roundtrip_seed_count_reflects_mode);
    tcase_add_test(tc, test_easy_roundtrip_set_bit_soup);
    tcase_add_test(tc, test_easy_roundtrip_set_lock_soup_couples_bit_soup);
    tcase_add_test(tc, test_easy_roundtrip_set_lock_seed_grows_seed_count);
    tcase_add_test(tc, test_easy_roundtrip_set_lock_seed_after_encrypt_rejected);
    tcase_add_test(tc, test_easy_roundtrip_set_nonce_bits_validation);
    tcase_add_test(tc, test_easy_roundtrip_set_barrier_fill_validation);
    tcase_add_test(tc, test_easy_roundtrip_set_chunk_size_accepted);
    tcase_add_test(tc, test_easy_roundtrip_two_encryptors_isolated);
    suite_add_tcase(s, tc);

    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int failures = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failures == 0 ? 0 : 1;
}
