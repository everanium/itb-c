/* Init → Save → Load → EncryptMessage → DecryptMessage round trip. */

#include "test_util.h"

static int run(void)
{
    itb_pipeline *sender = NULL;
    itb_status st = itb_pipeline_init("singlemsg-triple-mac-v1", NULL, &sender);
    TEST_OK(st, "init");
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    st = itb_pipeline_save(sender, &blob, &blob_len);
    TEST_OK(st, "save");
    TEST_ASSERT(blob_len > 0, "blob must be non-empty");
    TEST_ASSERT(blob != NULL, "blob pointer");
    itb_bytes_free(blob);

    itb_pipeline *receiver = NULL;
    st = test_load_from(sender, &receiver);
    TEST_OK(st, "load");

    static const uint8_t plain[] = "smoke round-trip payload";
    const size_t plain_len = sizeof(plain) - 1;

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    st = itb_pipeline_encrypt_message(sender, plain, plain_len,
                                      &wire, &wire_len);
    TEST_OK(st, "encrypt");
    TEST_ASSERT(wire_len != plain_len || memcmp(wire, plain, plain_len) != 0,
                "wire must differ from plaintext");

    uint8_t *back = NULL;
    size_t back_len = 0;
    st = itb_pipeline_decrypt_message(receiver, wire, wire_len,
                                      &back, &back_len);
    TEST_OK(st, "decrypt");
    TEST_ASSERT(back_len == plain_len, "length %zu != %zu", back_len, plain_len);
    TEST_ASSERT(memcmp(back, plain, plain_len) == 0, "payload mismatch");

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
