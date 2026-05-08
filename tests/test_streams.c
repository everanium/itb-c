/*
 * test_streams.c — chunked encrypt / decrypt over caller-owned I/O.
 *
 * Mirrors bindings/rust/tests/test_streams.rs one-to-one, adapted for
 * the C stream surface — itb_stream_encrypt / itb_stream_decrypt and
 * the Triple-Ouroboros counterparts. The C binding's stream API is
 * one-shot via callback pairs (read_fn / write_fn), not the
 * incremental StreamEncryptor / StreamDecryptor classes that Rust
 * exposes; the partial-feed semantics that Rust covers via
 * StreamDecryptor::feed are emulated here by a membuf_t that returns
 * data in arbitrary slices — the read_fn drains it across multiple
 * read calls and the chunk loop crosses chunk boundaries on every
 * pass.
 *
 * The Rust-only `test_write_after_close_raises` test has no direct C
 * analogue: the one-shot itb_stream_encrypt does not surface a
 * post-close handle a caller can write to. The truncated-stream
 * coverage from Rust's `test_partial_chunk_at_close_raises` IS
 * exercised here via a read callback that returns a header-only
 * prefix followed by EOF — itb_stream_decrypt surfaces ITB_BAD_INPUT
 * on the trailing incomplete chunk, matching the Rust path.
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
    size_t   len;       /* total bytes available to read */
    size_t   read_pos;  /* current read position */
    size_t   read_cap;  /* per-call read cap; 0 = no cap */
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

static uint8_t *pseudo_plaintext(size_t n) {
    uint8_t *p = (uint8_t *) malloc(n == 0 ? 1 : n);
    ck_assert_ptr_nonnull(p);
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t) (i & 0xff);
    }
    return p;
}

static uint8_t *pseudo_payload(size_t n) {
    uint8_t *p = (uint8_t *) malloc(n == 0 ? 1 : n);
    ck_assert_ptr_nonnull(p);
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t) (((i * 13u) + 11u) & 0xffu);
    }
    return p;
}

#define SMALL_CHUNK ((size_t) 4096)

START_TEST(test_streams_single_roundtrip_200kb)
{
    itb_seed_t *n = NULL, *d = NULL, *s = NULL;
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &n), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &d), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &s), ITB_OK);

    size_t pt_len = 200 * 1024;
    uint8_t *plaintext = pseudo_plaintext(pt_len);

    membuf_t in  = { plaintext, pt_len, pt_len, 0, 0 };
    membuf_t out = { NULL, 0, 0, 0, 0 };

    ck_assert_int_eq(itb_stream_encrypt(n, d, s,
                                        membuf_read, &in,
                                        membuf_write, &out,
                                        64 * 1024), ITB_OK);
    ck_assert_uint_gt(out.len, 0);
    ck_assert(out.len != pt_len || memcmp(out.data, plaintext, pt_len) != 0);

    /* Decrypt with a smaller per-call read cap so the chunk loop
     * crosses chunk boundaries on multiple iterations. */
    membuf_t cin = { out.data, out.len, out.len, 0, 4096 };
    membuf_t recovered = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_stream_decrypt(n, d, s,
                                        membuf_read, &cin,
                                        membuf_write, &recovered,
                                        4096), ITB_OK);
    ck_assert_uint_eq(recovered.len, pt_len);
    ck_assert_mem_eq(recovered.data, plaintext, pt_len);

    free(plaintext);
    free(out.data);
    free(recovered.data);
    itb_seed_free(n);
    itb_seed_free(d);
    itb_seed_free(s);
}
END_TEST

START_TEST(test_streams_single_roundtrip_short_payload)
{
    /* Payload smaller than chunk_size — exercises the EOF-flush path
     * that emits a single tail chunk. */
    itb_seed_t *n = NULL, *d = NULL, *s = NULL;
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &n), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &d), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &s), ITB_OK);

    static const uint8_t plaintext[] =
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
    size_t pt_len = sizeof(plaintext) - 1;

    membuf_t in  = { (uint8_t *) plaintext, pt_len, pt_len, 0, 0 };
    membuf_t out = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_stream_encrypt(n, d, s,
                                        membuf_read, &in,
                                        membuf_write, &out,
                                        64 * 1024), ITB_OK);

    membuf_t cin = { out.data, out.len, out.len, 0, 0 };
    membuf_t recovered = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_stream_decrypt(n, d, s,
                                        membuf_read, &cin,
                                        membuf_write, &recovered,
                                        64 * 1024), ITB_OK);
    ck_assert_uint_eq(recovered.len, pt_len);
    ck_assert_mem_eq(recovered.data, plaintext, pt_len);

    free(out.data);
    free(recovered.data);
    itb_seed_free(n);
    itb_seed_free(d);
    itb_seed_free(s);
}
END_TEST

START_TEST(test_streams_class_roundtrip_default_nonce)
{
    /* Equivalent of the Rust StreamEncryptor::new + write+write+close
     * incremental write path: feed the input source via the membuf in
     * arbitrary slices, exercise the small-chunk accumulator. */
    size_t pt_len = SMALL_CHUNK * 5 + 17;
    uint8_t *plaintext = pseudo_payload(pt_len);

    itb_seed_t *n = NULL, *d = NULL, *s = NULL;
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &n), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &d), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &s), ITB_OK);

    membuf_t in  = { plaintext, pt_len, pt_len, 0, 1000 }; /* short reads */
    membuf_t out = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_stream_encrypt(n, d, s,
                                        membuf_read, &in,
                                        membuf_write, &out,
                                        SMALL_CHUNK), ITB_OK);

    membuf_t cin = { out.data, out.len, out.len, 0, 1024 }; /* 1 KiB shards */
    membuf_t recovered = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_stream_decrypt(n, d, s,
                                        membuf_read, &cin,
                                        membuf_write, &recovered,
                                        SMALL_CHUNK), ITB_OK);
    ck_assert_uint_eq(recovered.len, pt_len);
    ck_assert_mem_eq(recovered.data, plaintext, pt_len);

    free(plaintext);
    free(out.data);
    free(recovered.data);
    itb_seed_free(n);
    itb_seed_free(d);
    itb_seed_free(s);
}
END_TEST

START_TEST(test_streams_encrypt_stream_decrypt_stream)
{
    size_t pt_len = SMALL_CHUNK * 4;
    uint8_t *plaintext = pseudo_payload(pt_len);

    itb_seed_t *n = NULL, *d = NULL, *s = NULL;
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &n), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &d), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &s), ITB_OK);

    membuf_t in  = { plaintext, pt_len, pt_len, 0, 0 };
    membuf_t out = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_stream_encrypt(n, d, s,
                                        membuf_read, &in,
                                        membuf_write, &out,
                                        SMALL_CHUNK), ITB_OK);

    membuf_t cin = { out.data, out.len, out.len, 0, 0 };
    membuf_t recovered = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_stream_decrypt(n, d, s,
                                        membuf_read, &cin,
                                        membuf_write, &recovered,
                                        SMALL_CHUNK), ITB_OK);
    ck_assert_uint_eq(recovered.len, pt_len);
    ck_assert_mem_eq(recovered.data, plaintext, pt_len);

    free(plaintext);
    free(out.data);
    free(recovered.data);
    itb_seed_free(n);
    itb_seed_free(d);
    itb_seed_free(s);
}
END_TEST

START_TEST(test_streams_class_roundtrip_default_nonce_triple)
{
    size_t pt_len = SMALL_CHUNK * 4 + 33;
    uint8_t *plaintext = pseudo_payload(pt_len);

    itb_seed_t *seeds[7] = {NULL};
    for (int k = 0; k < 7; k++) {
        ck_assert_int_eq(itb_seed_new("blake3", 1024, &seeds[k]), ITB_OK);
    }

    membuf_t in  = { plaintext, pt_len, pt_len, 0, 1000 };
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

    free(plaintext);
    free(out.data);
    free(recovered.data);
    for (int k = 0; k < 7; k++) itb_seed_free(seeds[k]);
}
END_TEST

START_TEST(test_streams_encrypt_stream_triple_decrypt_stream_triple)
{
    size_t pt_len = SMALL_CHUNK * 5 + 7;
    uint8_t *plaintext = pseudo_payload(pt_len);

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

    free(plaintext);
    free(out.data);
    free(recovered.data);
    for (int k = 0; k < 7; k++) itb_seed_free(seeds[k]);
}
END_TEST

START_TEST(test_streams_partial_chunk_at_close_raises)
{
    /* Equivalent of Rust's StreamDecryptor::close raising on a
     * truncated trailing chunk. The C path triggers ITB_BAD_INPUT
     * inside itb_stream_decrypt when read_fn signals EOF with a
     * non-empty accumulator. */
    itb_seed_t *n = NULL, *d = NULL, *s = NULL;
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &n), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &d), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &s), ITB_OK);

    /* Encrypt a tiny payload to obtain a real ciphertext from which a
     * truncated prefix can be carved. */
    static const uint8_t small_pt[] = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    size_t small_pt_len = sizeof(small_pt) - 1;
    membuf_t in  = { (uint8_t *) small_pt, small_pt_len, small_pt_len, 0, 0 };
    membuf_t out = { NULL, 0, 0, 0, 0 };
    ck_assert_int_eq(itb_stream_encrypt(n, d, s,
                                        membuf_read, &in,
                                        membuf_write, &out,
                                        SMALL_CHUNK), ITB_OK);
    ck_assert_uint_gt(out.len, 30);

    /* Decrypt only the first 30 bytes — header is complete (>= 20)
     * but the body is truncated. read_fn signals EOF after this
     * prefix; the chunk loop reports ITB_BAD_INPUT. */
    membuf_t cin = { out.data, out.len, 30, 0, 0 };
    membuf_t recovered = { NULL, 0, 0, 0, 0 };
    itb_status_t rc = itb_stream_decrypt(n, d, s,
                                         membuf_read, &cin,
                                         membuf_write, &recovered,
                                         SMALL_CHUNK);
    ck_assert_int_eq(rc, ITB_BAD_INPUT);

    free(out.data);
    free(recovered.data);
    itb_seed_free(n);
    itb_seed_free(d);
    itb_seed_free(s);
}
END_TEST

int main(void)
{
    Suite *s = suite_create("streams");
    TCase *tc = tcase_create("core");
    tcase_set_timeout(tc, 120);
    tcase_add_test(tc, test_streams_single_roundtrip_200kb);
    tcase_add_test(tc, test_streams_single_roundtrip_short_payload);
    tcase_add_test(tc, test_streams_class_roundtrip_default_nonce);
    tcase_add_test(tc, test_streams_encrypt_stream_decrypt_stream);
    tcase_add_test(tc, test_streams_class_roundtrip_default_nonce_triple);
    tcase_add_test(tc, test_streams_encrypt_stream_triple_decrypt_stream_triple);
    tcase_add_test(tc, test_streams_partial_chunk_at_close_raises);
    suite_add_tcase(s, tc);

    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int failures = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failures == 0 ? 0 : 1;
}
