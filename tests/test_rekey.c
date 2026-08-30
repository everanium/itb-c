/* Init → Rekey → Open receiver with the rotated blob → round trip. */

#include "test_util.h"

static int run(void)
{
    itb_pipeline *sender = NULL;
    itb_status st = itb_pipeline_init("singlemsg-triple-mac-v1", NULL, &sender);
    TEST_OK(st, "init");

    size_t before_len = itb_pipeline_blob_len(sender);
    uint8_t *before = malloc(before_len);
    TEST_ASSERT(before != NULL, "blob copy alloc");
    memcpy(before, itb_pipeline_blob(sender), before_len);

    uint8_t perm[32];
    uint8_t wrap[32];
    memset(perm, 0x11, sizeof(perm));
    memset(wrap, 0x22, sizeof(wrap));
    st = itb_pipeline_rekey(sender, perm, sizeof(perm), wrap, sizeof(wrap));
    TEST_OK(st, "rekey");
    TEST_ASSERT(itb_pipeline_blob_len(sender) != before_len ||
                    memcmp(itb_pipeline_blob(sender), before,
                           before_len) != 0,
                "rekey must refresh the blob");
    free(before);

    itb_pipeline *receiver = NULL;
    st = itb_pipeline_open("singlemsg-triple-mac-v1",
                           itb_pipeline_blob(sender),
                           itb_pipeline_blob_len(sender),
                           NULL, NULL, 0, NULL, 0, &receiver);
    TEST_OK(st, "open");

    static const uint8_t plain[] = "post-rekey payload";
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    st = itb_pipeline_encrypt_message(sender, plain, sizeof(plain) - 1,
                                      &wire, &wire_len);
    TEST_OK(st, "encrypt");

    uint8_t *back = NULL;
    size_t back_len = 0;
    st = itb_pipeline_decrypt_message(receiver, wire, wire_len,
                                      &back, &back_len);
    TEST_OK(st, "decrypt");
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
