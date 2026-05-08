/*
 * test_streams_nonce.c — streaming roundtrips across non-default nonce
 * sizes.
 *
 * Mirrors bindings/rust/tests/test_streams_nonce.rs one-to-one. Mutates
 * the process-global nonce_bits atomic to confirm the streaming path
 * tracks the active nonce size on every chunk header.
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

/* ------------------------------------------------------------------ */
/* In-memory ring buffer for stream callbacks                           */
/* ------------------------------------------------------------------ */
typedef struct {
    uint8_t *data;
    size_t   cap;
    size_t   len;
    size_t   read_pos;
    size_t   read_cap;
} membuf_t;

static int membuf_read(void *ctx, void *buf, size_t cap, size_t *out_n)
{
    membuf_t *m = (membuf_t *) ctx;
    size_t avail = m->len - m->read_pos;
    size_t want = (cap < avail) ? cap : avail;
    if (m->read_cap > 0 && want > m->read_cap) want = m->read_cap;
    if (want > 0) {
        memcpy(buf, m->data + m->read_pos, want);
        m->read_pos += want;
    }
    *out_n = want;
    return 0;
}

static int membuf_write(void *ctx, const void *buf, size_t n)
{
    membuf_t *m = (membuf_t *) ctx;
    if (m->len + n > m->cap) {
        size_t new_cap = m->cap == 0 ? 4096 : m->cap * 2;
        while (new_cap < m->len + n) new_cap *= 2;
        uint8_t *p = (uint8_t *) realloc(m->data, new_cap);
        if (p == NULL) return 1;
        m->data = p;
        m->cap = new_cap;
    }
    memcpy(m->data + m->len, buf, n);
    m->len += n;
    return 0;
}

static uint8_t *pseudo_payload(size_t n) {
    uint8_t *p = (uint8_t *) malloc(n == 0 ? 1 : n);
    ck_assert_ptr_nonnull(p);
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t) (((i * 31u) + 11u) & 0xffu);
    }
    return p;
}

#define SMALL_CHUNK ((size_t) 4096)

START_TEST(test_streams_nonce_class_roundtrip_non_default_nonce_single)
{
    int orig = itb_get_nonce_bits();
    size_t pt_len = SMALL_CHUNK * 3 + 100;
    uint8_t *plaintext = pseudo_payload(pt_len);

    static const int NONCES[] = {256, 512};
    for (size_t i = 0; i < sizeof(NONCES) / sizeof(NONCES[0]); i++) {
        ck_assert_int_eq(itb_set_nonce_bits(NONCES[i]), ITB_OK);

        itb_seed_t *noise = NULL, *data = NULL, *start = NULL;
        ck_assert_int_eq(itb_seed_new("blake3", 1024, &noise), ITB_OK);
        ck_assert_int_eq(itb_seed_new("blake3", 1024, &data),  ITB_OK);
        ck_assert_int_eq(itb_seed_new("blake3", 1024, &start), ITB_OK);

        membuf_t in  = { plaintext, pt_len, pt_len, 0, 1000 };
        membuf_t out = { NULL, 0, 0, 0, 0 };
        ck_assert_int_eq(itb_stream_encrypt(noise, data, start,
                                            membuf_read, &in,
                                            membuf_write, &out,
                                            SMALL_CHUNK), ITB_OK);

        membuf_t cin = { out.data, out.len, out.len, 0, 0 };
        membuf_t recovered = { NULL, 0, 0, 0, 0 };
        ck_assert_int_eq(itb_stream_decrypt(noise, data, start,
                                            membuf_read, &cin,
                                            membuf_write, &recovered,
                                            SMALL_CHUNK), ITB_OK);
        ck_assert_uint_eq(recovered.len, pt_len);
        ck_assert_mem_eq(recovered.data, plaintext, pt_len);

        free(out.data);
        free(recovered.data);
        itb_seed_free(noise);
        itb_seed_free(data);
        itb_seed_free(start);
    }
    free(plaintext);
    ck_assert_int_eq(itb_set_nonce_bits(orig), ITB_OK);
}
END_TEST

START_TEST(test_streams_nonce_encrypt_stream_across_nonce_sizes_single)
{
    int orig = itb_get_nonce_bits();
    size_t pt_len = SMALL_CHUNK * 3 + 256;
    uint8_t *plaintext = pseudo_payload(pt_len);

    static const int NONCES[] = {128, 256, 512};
    for (size_t i = 0; i < sizeof(NONCES) / sizeof(NONCES[0]); i++) {
        ck_assert_int_eq(itb_set_nonce_bits(NONCES[i]), ITB_OK);

        itb_seed_t *noise = NULL, *data = NULL, *start = NULL;
        ck_assert_int_eq(itb_seed_new("blake3", 1024, &noise), ITB_OK);
        ck_assert_int_eq(itb_seed_new("blake3", 1024, &data),  ITB_OK);
        ck_assert_int_eq(itb_seed_new("blake3", 1024, &start), ITB_OK);

        membuf_t in  = { plaintext, pt_len, pt_len, 0, 0 };
        membuf_t out = { NULL, 0, 0, 0, 0 };
        ck_assert_int_eq(itb_stream_encrypt(noise, data, start,
                                            membuf_read, &in,
                                            membuf_write, &out,
                                            SMALL_CHUNK), ITB_OK);

        membuf_t cin = { out.data, out.len, out.len, 0, 0 };
        membuf_t recovered = { NULL, 0, 0, 0, 0 };
        ck_assert_int_eq(itb_stream_decrypt(noise, data, start,
                                            membuf_read, &cin,
                                            membuf_write, &recovered,
                                            SMALL_CHUNK), ITB_OK);
        ck_assert_uint_eq(recovered.len, pt_len);
        ck_assert_mem_eq(recovered.data, plaintext, pt_len);

        free(out.data);
        free(recovered.data);
        itb_seed_free(noise);
        itb_seed_free(data);
        itb_seed_free(start);
    }
    free(plaintext);
    ck_assert_int_eq(itb_set_nonce_bits(orig), ITB_OK);
}
END_TEST

START_TEST(test_streams_nonce_class_roundtrip_non_default_nonce_triple)
{
    int orig = itb_get_nonce_bits();
    size_t pt_len = SMALL_CHUNK * 3;
    uint8_t *plaintext = pseudo_payload(pt_len);

    static const int NONCES[] = {256, 512};
    for (size_t i = 0; i < sizeof(NONCES) / sizeof(NONCES[0]); i++) {
        ck_assert_int_eq(itb_set_nonce_bits(NONCES[i]), ITB_OK);

        itb_seed_t *seeds[7] = {NULL};
        for (int k = 0; k < 7; k++) {
            ck_assert_int_eq(itb_seed_new("blake3", 1024, &seeds[k]), ITB_OK);
        }

        membuf_t in  = { plaintext, pt_len, pt_len, 0, 1024 };
        membuf_t out = { NULL, 0, 0, 0, 0 };
        ck_assert_int_eq(itb_stream_encrypt_triple(seeds[0], seeds[1], seeds[2], seeds[3],
                                                   seeds[4], seeds[5], seeds[6],
                                                   membuf_read, &in,
                                                   membuf_write, &out,
                                                   SMALL_CHUNK), ITB_OK);

        membuf_t cin = { out.data, out.len, out.len, 0, 0 };
        membuf_t recovered = { NULL, 0, 0, 0, 0 };
        ck_assert_int_eq(itb_stream_decrypt_triple(seeds[0], seeds[1], seeds[2], seeds[3],
                                                   seeds[4], seeds[5], seeds[6],
                                                   membuf_read, &cin,
                                                   membuf_write, &recovered,
                                                   SMALL_CHUNK), ITB_OK);
        ck_assert_uint_eq(recovered.len, pt_len);
        ck_assert_mem_eq(recovered.data, plaintext, pt_len);

        free(out.data);
        free(recovered.data);
        for (int k = 0; k < 7; k++) itb_seed_free(seeds[k]);
    }
    free(plaintext);
    ck_assert_int_eq(itb_set_nonce_bits(orig), ITB_OK);
}
END_TEST

START_TEST(test_streams_nonce_encrypt_stream_triple_across_nonce_sizes)
{
    int orig = itb_get_nonce_bits();
    size_t pt_len = SMALL_CHUNK * 3 + 100;
    uint8_t *plaintext = pseudo_payload(pt_len);

    static const int NONCES[] = {128, 256, 512};
    for (size_t i = 0; i < sizeof(NONCES) / sizeof(NONCES[0]); i++) {
        ck_assert_int_eq(itb_set_nonce_bits(NONCES[i]), ITB_OK);

        itb_seed_t *seeds[7] = {NULL};
        for (int k = 0; k < 7; k++) {
            ck_assert_int_eq(itb_seed_new("blake3", 1024, &seeds[k]), ITB_OK);
        }

        membuf_t in  = { plaintext, pt_len, pt_len, 0, 0 };
        membuf_t out = { NULL, 0, 0, 0, 0 };
        ck_assert_int_eq(itb_stream_encrypt_triple(seeds[0], seeds[1], seeds[2], seeds[3],
                                                   seeds[4], seeds[5], seeds[6],
                                                   membuf_read, &in,
                                                   membuf_write, &out,
                                                   SMALL_CHUNK), ITB_OK);

        membuf_t cin = { out.data, out.len, out.len, 0, 0 };
        membuf_t recovered = { NULL, 0, 0, 0, 0 };
        ck_assert_int_eq(itb_stream_decrypt_triple(seeds[0], seeds[1], seeds[2], seeds[3],
                                                   seeds[4], seeds[5], seeds[6],
                                                   membuf_read, &cin,
                                                   membuf_write, &recovered,
                                                   SMALL_CHUNK), ITB_OK);
        ck_assert_uint_eq(recovered.len, pt_len);
        ck_assert_mem_eq(recovered.data, plaintext, pt_len);

        free(out.data);
        free(recovered.data);
        for (int k = 0; k < 7; k++) itb_seed_free(seeds[k]);
    }
    free(plaintext);
    ck_assert_int_eq(itb_set_nonce_bits(orig), ITB_OK);
}
END_TEST

int main(void)
{
    Suite *s = suite_create("streams_nonce");
    TCase *tc = tcase_create("core");
    tcase_set_timeout(tc, 120);
    tcase_add_test(tc, test_streams_nonce_class_roundtrip_non_default_nonce_single);
    tcase_add_test(tc, test_streams_nonce_encrypt_stream_across_nonce_sizes_single);
    tcase_add_test(tc, test_streams_nonce_class_roundtrip_non_default_nonce_triple);
    tcase_add_test(tc, test_streams_nonce_encrypt_stream_triple_across_nonce_sizes);
    suite_add_tcase(s, tc);

    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int failures = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failures == 0 ? 0 : 1;
}
