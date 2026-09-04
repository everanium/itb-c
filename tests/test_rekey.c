/* Init → Rekey → Load receiver with the rotated blob → round trip. */

#include "test_util.h"

static int run(void)
{
    itb_pipeline *sender = NULL;
    itb_status st = itb_pipeline_init("singlemsg-triple-mac-v1", NULL, &sender);
    TEST_OK(st, "init");

    uint8_t *before = NULL;
    size_t before_len = 0;
    st = itb_pipeline_save(sender, &before, &before_len);
    TEST_OK(st, "save before");

    uint8_t perm[32];
    uint8_t wrap[32];
    memset(perm, 0x11, sizeof(perm));
    memset(wrap, 0x22, sizeof(wrap));
    uint8_t *rotated = NULL;
    size_t rotated_len = 0;
    st = itb_pipeline_rekey(sender, perm, sizeof(perm), wrap, sizeof(wrap),
                            &rotated, &rotated_len);
    TEST_OK(st, "rekey");
    TEST_ASSERT(rotated_len != before_len ||
                    memcmp(rotated, before, before_len) != 0,
                "rekey must refresh the blob");
    itb_bytes_free(before);

    /* save reports the rotated blob. */
    uint8_t *after = NULL;
    size_t after_len = 0;
    st = itb_pipeline_save(sender, &after, &after_len);
    TEST_OK(st, "save after");
    TEST_ASSERT(after_len == rotated_len && memcmp(after, rotated, after_len) == 0,
                "save must report the rotated blob");
    itb_bytes_free(after);

    itb_pipeline *receiver = NULL;
    st = itb_pipeline_load(rotated, rotated_len, NULL, 0, NULL, 0, &receiver);
    TEST_OK(st, "load");
    itb_bytes_free(rotated);

    /* A NULL out pair discards the rekey bytes. */
    memset(perm, 0x33, sizeof(perm));
    st = itb_pipeline_rekey(receiver, perm, sizeof(perm), wrap, sizeof(wrap),
                            NULL, NULL);
    TEST_OK(st, "rekey discard");
    st = itb_pipeline_rekey(sender, perm, sizeof(perm), wrap, sizeof(wrap),
                            NULL, NULL);
    TEST_OK(st, "rekey sender");

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
