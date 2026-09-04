/* Freeing an encrypt session mid-flight releases resources cleanly
 * and leaves the Pipeline usable. The process exiting without hang or
 * crash (and valgrind / ASan reporting no leak) is the assertion. */

#include "test_util.h"

static int run(void)
{
    itb_pipeline *sender = NULL;
    itb_status st = itb_pipeline_init("streaming-aead-triple-mac-v1", NULL,
                                      &sender);
    TEST_OK(st, "init");

    uint8_t *chunk = test_payload(100000, 0xA5A5A5A5u);
    TEST_ASSERT(chunk != NULL, "payload alloc");

    itb_stream *sess = NULL;
    st = itb_pipeline_encrypt_stream_begin(sender, &sess);
    TEST_OK(st, "begin");
    st = itb_stream_write(sess, chunk, 100000);
    TEST_OK(st, "write");
    /* Freed here without end() — StreamFree cancels the session. */
    itb_stream_free(sess);
    free(chunk);

    /* The Pipeline stays usable after the cancelled session. */
    itb_pipeline *receiver = NULL;
    st = test_load_from(sender, &receiver);
    TEST_OK(st, "load");

    static const uint8_t plain[] = "after cancel";
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    st = itb_pipeline_encrypt_message(sender, plain, sizeof(plain) - 1,
                                      &wire, &wire_len);
    TEST_OK(st, "encrypt after cancel");

    uint8_t *back = NULL;
    size_t back_len = 0;
    st = itb_pipeline_decrypt_message(receiver, wire, wire_len,
                                      &back, &back_len);
    TEST_OK(st, "decrypt after cancel");
    TEST_ASSERT(back_len == sizeof(plain) - 1 &&
                    memcmp(back, plain, back_len) == 0,
                "payload mismatch");

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
