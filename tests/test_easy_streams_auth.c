/*
 * test_easy_streams_auth.c — encryptor-bound Streaming AEAD round-trip
 * + tamper detection over itb_encryptor_stream_encrypt_auth /
 * itb_encryptor_stream_decrypt_auth.
 *
 * Mirrors the shape of test_streams_auth.c at the high-level Encryptor
 * surface. The encryptor's bound MAC closure is reused across every
 * chunk; the helper supplies the Streaming AEAD binding components.
 *
 * Per-binary fork() isolation gives each test its own libitb global
 * state.
 */

#include <check.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "itb.h"

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

static uint8_t *pseudo_payload(size_t n)
{
    uint8_t *p = (uint8_t *) malloc(n == 0 ? 1 : n);
    ck_assert_ptr_nonnull(p);
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t) (((i * 31u) + 17u) & 0xffu);
    }
    return p;
}

#define SMALL_CHUNK ((size_t) 4096)

START_TEST(test_easy_auth_single_roundtrip_default)
{
    itb_encryptor_t *e = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, NULL, 1, &e), ITB_OK);
    ck_assert_ptr_nonnull(e);

    /* Replicate the encryptor by exporting + importing into a second
     * instance — the two encryptors share the same MAC + PRF + seed
     * material, mirroring the cross-stream verify-side pattern. */
    uint8_t *blob = NULL; size_t blob_len = 0;
    ck_assert_int_eq(itb_encryptor_export(e, &blob, &blob_len), ITB_OK);
    itb_encryptor_t *e2 = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, NULL, 1, &e2), ITB_OK);
    ck_assert_int_eq(itb_encryptor_import(e2, blob, blob_len), ITB_OK);
    itb_buffer_free(blob);

    size_t pt_len = SMALL_CHUNK * 3 + 13;
    uint8_t *pt = pseudo_payload(pt_len);
    membuf_t in  = { pt, pt_len, pt_len, 0, 0 };
    membuf_t out = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_encryptor_stream_encrypt_auth(e,
                        membuf_read, &in, membuf_write, &out,
                        SMALL_CHUNK), ITB_OK);

    membuf_t cin = { out.data, out.len, out.len, 0, 0 };
    membuf_t recovered = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_encryptor_stream_decrypt_auth(e2,
                        membuf_read, &cin, membuf_write, &recovered,
                        SMALL_CHUNK), ITB_OK);
    ck_assert_uint_eq(recovered.len, pt_len);
    ck_assert_mem_eq(recovered.data, pt, pt_len);

    free(pt);
    free(out.data);
    free(recovered.data);
    itb_encryptor_free(e);
    itb_encryptor_free(e2);
}
END_TEST

START_TEST(test_easy_auth_triple_roundtrip)
{
    itb_encryptor_t *e = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 3, &e),
                     ITB_OK);
    uint8_t *blob = NULL; size_t blob_len = 0;
    ck_assert_int_eq(itb_encryptor_export(e, &blob, &blob_len), ITB_OK);
    itb_encryptor_t *e2 = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, "kmac256", 3, &e2),
                     ITB_OK);
    ck_assert_int_eq(itb_encryptor_import(e2, blob, blob_len), ITB_OK);
    itb_buffer_free(blob);

    size_t pt_len = SMALL_CHUNK * 2 + 47;
    uint8_t *pt = pseudo_payload(pt_len);
    membuf_t in  = { pt, pt_len, pt_len, 0, 1024 };
    membuf_t out = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_encryptor_stream_encrypt_auth(e,
                        membuf_read, &in, membuf_write, &out,
                        SMALL_CHUNK), ITB_OK);

    membuf_t cin = { out.data, out.len, out.len, 0, 1024 };
    membuf_t recovered = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_encryptor_stream_decrypt_auth(e2,
                        membuf_read, &cin, membuf_write, &recovered,
                        SMALL_CHUNK), ITB_OK);
    ck_assert_uint_eq(recovered.len, pt_len);
    ck_assert_mem_eq(recovered.data, pt, pt_len);

    free(pt);
    free(out.data);
    free(recovered.data);
    itb_encryptor_free(e);
    itb_encryptor_free(e2);
}
END_TEST

START_TEST(test_easy_auth_empty_stream)
{
    itb_encryptor_t *e = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, NULL, 1, &e), ITB_OK);
    uint8_t *blob = NULL; size_t blob_len = 0;
    ck_assert_int_eq(itb_encryptor_export(e, &blob, &blob_len), ITB_OK);
    itb_encryptor_t *e2 = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, NULL, 1, &e2), ITB_OK);
    ck_assert_int_eq(itb_encryptor_import(e2, blob, blob_len), ITB_OK);
    itb_buffer_free(blob);

    membuf_t in  = { NULL, 0, 0, 0, 0 };
    membuf_t out = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_encryptor_stream_encrypt_auth(e,
                        membuf_read, &in, membuf_write, &out,
                        SMALL_CHUNK), ITB_OK);
    ck_assert_uint_gt(out.len, 32u);

    membuf_t cin = { out.data, out.len, out.len, 0, 0 };
    membuf_t recovered = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_encryptor_stream_decrypt_auth(e2,
                        membuf_read, &cin, membuf_write, &recovered,
                        SMALL_CHUNK), ITB_OK);
    ck_assert_uint_eq(recovered.len, 0u);

    free(out.data);
    free(recovered.data);
    itb_encryptor_free(e);
    itb_encryptor_free(e2);
}
END_TEST

START_TEST(test_easy_auth_truncate_tail)
{
    itb_encryptor_t *e = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, NULL, 1, &e), ITB_OK);
    uint8_t *blob = NULL; size_t blob_len = 0;
    ck_assert_int_eq(itb_encryptor_export(e, &blob, &blob_len), ITB_OK);
    itb_encryptor_t *e2 = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, NULL, 1, &e2), ITB_OK);
    ck_assert_int_eq(itb_encryptor_import(e2, blob, blob_len), ITB_OK);
    itb_buffer_free(blob);

    size_t pt_len = SMALL_CHUNK * 3 - 5;
    uint8_t *pt = pseudo_payload(pt_len);
    membuf_t in  = { pt, pt_len, pt_len, 0, 0 };
    membuf_t out = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_encryptor_stream_encrypt_auth(e,
                        membuf_read, &in, membuf_write, &out,
                        SMALL_CHUNK), ITB_OK);

    int hsz = 0;
    ck_assert_int_eq(itb_encryptor_header_size(e, &hsz), ITB_OK);
    /* Walk the wire to find chunk 2 start offset. */
    size_t cur = 32;
    size_t cl = 0;
    ck_assert_int_eq(itb_encryptor_parse_chunk_len(e, out.data + cur,
                                                   (size_t) hsz, &cl), ITB_OK);
    cur += cl;
    ck_assert_int_eq(itb_encryptor_parse_chunk_len(e, out.data + cur,
                                                   (size_t) hsz, &cl), ITB_OK);
    cur += cl;
    /* `cur` now sits at the start of chunk 2 (the terminating chunk).
     * Truncate by feeding only chunks 0 and 1. */
    size_t truncated_len = cur;

    membuf_t cin = { out.data, out.len, truncated_len, 0, 0 };
    membuf_t recovered = { NULL, 0, 0, 0, 0 };
    itb_status_t rc = itb_encryptor_stream_decrypt_auth(e2,
                        membuf_read, &cin, membuf_write, &recovered,
                        SMALL_CHUNK);
    ck_assert_int_eq(rc, ITB_STREAM_TRUNCATED);

    free(pt);
    free(out.data);
    free(recovered.data);
    itb_encryptor_free(e);
    itb_encryptor_free(e2);
}
END_TEST

START_TEST(test_easy_auth_closed_encryptor_preflight)
{
    itb_encryptor_t *e = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, NULL, 1, &e), ITB_OK);
    ck_assert_int_eq(itb_encryptor_close(e), ITB_OK);

    membuf_t in  = { NULL, 0, 0, 0, 0 };
    membuf_t out = { NULL, 0, 0, 0, 0 };
    itb_status_t rc = itb_encryptor_stream_encrypt_auth(e,
                        membuf_read, &in, membuf_write, &out,
                        SMALL_CHUNK);
    ck_assert_int_eq(rc, ITB_EASY_CLOSED);

    rc = itb_encryptor_stream_decrypt_auth(e,
                        membuf_read, &in, membuf_write, &out,
                        SMALL_CHUNK);
    ck_assert_int_eq(rc, ITB_EASY_CLOSED);

    itb_encryptor_free(e);
}
END_TEST

START_TEST(test_easy_auth_chunk_size_zero_rejected)
{
    itb_encryptor_t *e = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, NULL, 1, &e), ITB_OK);

    membuf_t in  = { NULL, 0, 0, 0, 0 };
    membuf_t out = { NULL, 0, 0, 0, 0 };
    itb_status_t rc = itb_encryptor_stream_encrypt_auth(e,
                        membuf_read, &in, membuf_write, &out,
                        0);
    ck_assert_int_eq(rc, ITB_BAD_INPUT);

    itb_encryptor_free(e);
}
END_TEST

START_TEST(test_easy_auth_stream_prefix_tamper)
{
    itb_encryptor_t *e = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, NULL, 1, &e), ITB_OK);
    uint8_t *blob = NULL; size_t blob_len = 0;
    ck_assert_int_eq(itb_encryptor_export(e, &blob, &blob_len), ITB_OK);
    itb_encryptor_t *e2 = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, NULL, 1, &e2), ITB_OK);
    ck_assert_int_eq(itb_encryptor_import(e2, blob, blob_len), ITB_OK);
    itb_buffer_free(blob);

    size_t pt_len = 500;
    uint8_t *pt = pseudo_payload(pt_len);
    membuf_t in  = { pt, pt_len, pt_len, 0, 0 };
    membuf_t out = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_encryptor_stream_encrypt_auth(e,
                        membuf_read, &in, membuf_write, &out,
                        SMALL_CHUNK), ITB_OK);

    /* Flip a byte inside the 32-byte stream_id prefix. */
    out.data[10] ^= 0x33;

    membuf_t cin = { out.data, out.len, out.len, 0, 0 };
    membuf_t recovered = { NULL, 0, 0, 0, 0 };
    itb_status_t rc = itb_encryptor_stream_decrypt_auth(e2,
                        membuf_read, &cin, membuf_write, &recovered,
                        SMALL_CHUNK);
    ck_assert_int_eq(rc, ITB_MAC_FAILURE);

    free(pt);
    free(out.data);
    free(recovered.data);
    itb_encryptor_free(e);
    itb_encryptor_free(e2);
}
END_TEST

/*
 * Regression: per-instance nonce_bits must drive the auth-stream
 * decoder's chunk-length parse, not the process-global setting. The
 * three tests below pin the contract that itb_encryptor_set_nonce_bits
 * is honoured even when itb_set_nonce_bits is left at a divergent
 * default. The third test is the pointed regression — it deliberately
 * holds the global at 128 while flipping the encryptor to 512.
 */

static void run_paired_auth_roundtrip_nonce_bits(int nonce_bits, int mode,
                                                   const char *mac_name)
{
    itb_encryptor_t *e = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, mac_name, mode, &e),
                     ITB_OK);
    ck_assert_int_eq(itb_encryptor_set_nonce_bits(e, nonce_bits), ITB_OK);

    uint8_t *blob = NULL; size_t blob_len = 0;
    ck_assert_int_eq(itb_encryptor_export(e, &blob, &blob_len), ITB_OK);
    itb_encryptor_t *e2 = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, mac_name, mode, &e2),
                     ITB_OK);
    ck_assert_int_eq(itb_encryptor_set_nonce_bits(e2, nonce_bits), ITB_OK);
    ck_assert_int_eq(itb_encryptor_import(e2, blob, blob_len), ITB_OK);
    itb_buffer_free(blob);

    /* ~96 KiB plaintext -> multi-chunk wire at SMALL_CHUNK = 4096. */
    size_t pt_len = SMALL_CHUNK * 24 + 17;
    uint8_t *pt = pseudo_payload(pt_len);
    membuf_t in  = { pt, pt_len, pt_len, 0, 0 };
    membuf_t out = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_encryptor_stream_encrypt_auth(e,
                        membuf_read, &in, membuf_write, &out,
                        SMALL_CHUNK), ITB_OK);

    membuf_t cin = { out.data, out.len, out.len, 0, 0 };
    membuf_t recovered = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_encryptor_stream_decrypt_auth(e2,
                        membuf_read, &cin, membuf_write, &recovered,
                        SMALL_CHUNK), ITB_OK);
    ck_assert_uint_eq(recovered.len, pt_len);
    ck_assert_mem_eq(recovered.data, pt, pt_len);

    free(pt);
    free(out.data);
    free(recovered.data);
    itb_encryptor_free(e);
    itb_encryptor_free(e2);
}

START_TEST(test_easy_auth_roundtrip_non_default_nonce_single)
{
    static const int NONCE_BITS[] = { 256, 512 };
    for (size_t i = 0; i < sizeof(NONCE_BITS) / sizeof(NONCE_BITS[0]); i++) {
        run_paired_auth_roundtrip_nonce_bits(NONCE_BITS[i], 1, NULL);
    }
}
END_TEST

START_TEST(test_easy_auth_roundtrip_non_default_nonce_triple)
{
    static const int NONCE_BITS[] = { 256, 512 };
    for (size_t i = 0; i < sizeof(NONCE_BITS) / sizeof(NONCE_BITS[0]); i++) {
        run_paired_auth_roundtrip_nonce_bits(NONCE_BITS[i], 3, "kmac256");
    }
}
END_TEST

START_TEST(test_easy_auth_roundtrip_global_diverges_from_instance)
{
    /* Pin the process-global at 128 (the default). The per-instance
     * value is then bumped to 512. Decryption must still succeed; if
     * the auth-stream parser silently consults the global, chunk_len
     * mismatches and the round-trip fails. */
    ck_assert_int_eq(itb_set_nonce_bits(128), ITB_OK);
    ck_assert_int_eq(itb_get_nonce_bits(), 128);

    itb_encryptor_t *e = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, NULL, 1, &e), ITB_OK);
    ck_assert_int_eq(itb_encryptor_set_nonce_bits(e, 512), ITB_OK);

    uint8_t *blob = NULL; size_t blob_len = 0;
    ck_assert_int_eq(itb_encryptor_export(e, &blob, &blob_len), ITB_OK);
    itb_encryptor_t *e2 = NULL;
    ck_assert_int_eq(itb_encryptor_new("blake3", 1024, NULL, 1, &e2), ITB_OK);
    ck_assert_int_eq(itb_encryptor_set_nonce_bits(e2, 512), ITB_OK);
    ck_assert_int_eq(itb_encryptor_import(e2, blob, blob_len), ITB_OK);
    itb_buffer_free(blob);

    /* Confirm the global is still 128 — the per-instance set must not
     * have leaked into the global. */
    ck_assert_int_eq(itb_get_nonce_bits(), 128);

    size_t pt_len = SMALL_CHUNK * 24 + 17;
    uint8_t *pt = pseudo_payload(pt_len);
    membuf_t in  = { pt, pt_len, pt_len, 0, 0 };
    membuf_t out = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_encryptor_stream_encrypt_auth(e,
                        membuf_read, &in, membuf_write, &out,
                        SMALL_CHUNK), ITB_OK);

    membuf_t cin = { out.data, out.len, out.len, 0, 0 };
    membuf_t recovered = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_encryptor_stream_decrypt_auth(e2,
                        membuf_read, &cin, membuf_write, &recovered,
                        SMALL_CHUNK), ITB_OK);
    ck_assert_uint_eq(recovered.len, pt_len);
    ck_assert_mem_eq(recovered.data, pt, pt_len);

    free(pt);
    free(out.data);
    free(recovered.data);
    itb_encryptor_free(e);
    itb_encryptor_free(e2);
}
END_TEST

int main(void)
{
    Suite *s = suite_create("easy_streams_auth");
    TCase *tc = tcase_create("core");
    tcase_set_timeout(tc, 180);
    tcase_add_test(tc, test_easy_auth_single_roundtrip_default);
    tcase_add_test(tc, test_easy_auth_triple_roundtrip);
    tcase_add_test(tc, test_easy_auth_empty_stream);
    tcase_add_test(tc, test_easy_auth_truncate_tail);
    tcase_add_test(tc, test_easy_auth_closed_encryptor_preflight);
    tcase_add_test(tc, test_easy_auth_chunk_size_zero_rejected);
    tcase_add_test(tc, test_easy_auth_stream_prefix_tamper);
    tcase_add_test(tc, test_easy_auth_roundtrip_non_default_nonce_single);
    tcase_add_test(tc, test_easy_auth_roundtrip_non_default_nonce_triple);
    tcase_add_test(tc, test_easy_auth_roundtrip_global_diverges_from_instance);
    suite_add_tcase(s, tc);

    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int failures = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failures == 0 ? 0 : 1;
}
