/* Explicit write / end / read round trip with pathological batch
 * sizes (17-byte feed, 23-byte drain) across multiple chunks. */

#include "test_util.h"

/* Feeds src in 17-byte writes, ends, drains in 23-byte reads into a
 * malloc'd buffer (*out / *out_len). Returns non-zero on failure. */
static int feed_drain(const itb_pipeline *pipe, int encrypt,
                      const uint8_t *src, size_t src_len,
                      uint8_t **out, size_t *out_len)
{
    itb_stream *sess = NULL;
    itb_status st = encrypt
        ? itb_pipeline_encrypt_stream_begin(pipe, &sess)
        : itb_pipeline_decrypt_stream_begin(pipe, &sess);
    TEST_OK(st, "begin");

    for (size_t off = 0; off < src_len; off += 17) {
        size_t n = src_len - off < 17 ? src_len - off : 17;
        st = itb_stream_write(sess, src + off, n);
        TEST_OK(st, "write");
    }
    st = itb_stream_end(sess);
    TEST_OK(st, "end");

    size_t cap = 4096;
    uint8_t *buf = malloc(cap);
    TEST_ASSERT(buf != NULL, "drain alloc");
    size_t len = 0;
    for (;;) {
        uint8_t piece[23];
        size_t n = 0;
        int fin = 0;
        st = itb_stream_read(sess, piece, sizeof(piece), &n, &fin);
        TEST_OK(st, "read");
        if (len + n > cap) {
            cap *= 2;
            uint8_t *grown = realloc(buf, cap);
            TEST_ASSERT(grown != NULL, "drain realloc");
            buf = grown;
        }
        memcpy(buf + len, piece, n);
        len += n;
        if (fin) {
            break;
        }
    }
    itb_stream_free(sess);
    *out = buf;
    *out_len = len;
    return 0;
}

static int run(void)
{
    /* Small chunk size so the 64 KiB payload spans many chunks. */
    itb_opts *opts = itb_opts_new();
    TEST_ASSERT(opts != NULL, "opts alloc");
    itb_status st = itb_opts_set(opts, "chunkSize", "4096");
    TEST_OK(st, "opts set");

    itb_pipeline *sender = NULL;
    st = itb_pipeline_init("streaming-aead-triple-mac-v1", opts, &sender);
    TEST_OK(st, "init");

    itb_pipeline *receiver = NULL;
    st = test_load_from(sender, &receiver);
    TEST_OK(st, "load");
    itb_opts_free(opts);

    const size_t size = 65536;
    uint8_t *plain = malloc(size);
    TEST_ASSERT(plain != NULL, "payload alloc");
    for (size_t i = 0; i < size; i++) {
        plain[i] = (uint8_t)(i % 241);
    }

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    int rc = feed_drain(sender, 1, plain, size, &wire, &wire_len);
    if (rc != 0) {
        return rc;
    }
    TEST_ASSERT(wire_len > 0, "wire must be non-empty");

    uint8_t *back = NULL;
    size_t back_len = 0;
    rc = feed_drain(receiver, 0, wire, wire_len, &back, &back_len);
    if (rc != 0) {
        return rc;
    }
    TEST_ASSERT(back_len == size, "length %zu != %zu", back_len, size);
    TEST_ASSERT(memcmp(back, plain, size) == 0, "payload mismatch");

    free(plain);
    free(wire);
    free(back);
    itb_pipeline_free(receiver);
    itb_pipeline_free(sender);
    return 0;
}

int main(void)
{
    return run();
}
