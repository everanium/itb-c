/* Round trip through the whole-buffer stream pumps on a Streaming
 * AEAD profile at 1 MiB. */

#include "test_util.h"

static int run(void)
{
    itb_pipeline *sender = NULL;
    itb_status st = itb_pipeline_init("streaming-aead-triple-mac-v1", NULL,
                                      &sender);
    TEST_OK(st, "init");

    itb_pipeline *receiver = NULL;
    st = itb_pipeline_open("streaming-aead-triple-mac-v1",
                           itb_pipeline_blob(sender),
                           itb_pipeline_blob_len(sender),
                           NULL, NULL, 0, NULL, 0, &receiver);
    TEST_OK(st, "open");

    const size_t size = (size_t)1 << 20;
    uint8_t *plain = test_payload(size, 0x9E3779B9u);
    TEST_ASSERT(plain != NULL, "payload alloc");

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    st = itb_pipeline_encrypt_stream_pump(sender, plain, size,
                                          &wire, &wire_len);
    TEST_OK(st, "encrypt pump");
    TEST_ASSERT(wire_len > 0, "wire must be non-empty");

    uint8_t *back = NULL;
    size_t back_len = 0;
    st = itb_pipeline_decrypt_stream_pump(receiver, wire, wire_len,
                                          &back, &back_len);
    TEST_OK(st, "decrypt pump");
    TEST_ASSERT(back_len == size, "length %zu != %zu", back_len, size);
    TEST_ASSERT(memcmp(back, plain, size) == 0, "payload mismatch");

    free(plain);
    itb_bytes_free(wire);
    itb_bytes_free(back);
    itb_pipeline_free(receiver);
    itb_pipeline_free(sender);
    return 0;
}

int main(void)
{
    return run();
}
