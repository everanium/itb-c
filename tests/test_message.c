/* Single Message round trip across every shipped cipher-bearing
 * profile at small (4 KiB) and medium (256 KiB) payloads. The
 * blob-only profile has no cipher surface and is exercised in
 * test_errors.c instead. */

#include "test_util.h"

static int round_trip(const char *profile, size_t size)
{
    itb_pipeline *sender = NULL;
    itb_status st = itb_pipeline_init(profile, NULL, &sender);
    TEST_OK(st, profile);

    itb_pipeline *receiver = NULL;
    st = test_load_from(sender, &receiver);
    TEST_OK(st, profile);

    uint8_t *plain = test_payload(size, (uint64_t)size);
    TEST_ASSERT(plain != NULL, "payload alloc");

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    st = itb_pipeline_encrypt_message(sender, plain, size, &wire, &wire_len);
    TEST_OK(st, profile);

    uint8_t *back = NULL;
    size_t back_len = 0;
    st = itb_pipeline_decrypt_message(receiver, wire, wire_len,
                                      &back, &back_len);
    TEST_OK(st, profile);
    TEST_ASSERT(back_len == size, "%s @%zu: length %zu", profile, size, back_len);
    TEST_ASSERT(memcmp(back, plain, size) == 0, "%s @%zu: mismatch",
                profile, size);

    free(plain);
    itb_bytes_free(wire);
    itb_bytes_free(back);
    itb_pipeline_free(receiver);
    itb_pipeline_free(sender);
    return 0;
}

int main(void)
{
    static const char *const profiles[] = {
        "streaming-aead-triple-mac-v1",
        "streaming-noaead-triple-v1",
        "singlemsg-triple-mac-v1",
        "singlemsg-triple-nomac-v1",
        "streaming-aead-triple-mac-mixed-v1",
        "streaming-noaead-triple-mixed-v1",
        "singlemsg-triple-mac-mixed-v1",
        "singlemsg-triple-nomac-mixed-v1",
    };
    static const size_t sizes[] = { 4 * 1024, 256 * 1024 };
    for (size_t p = 0; p < sizeof(profiles) / sizeof(profiles[0]); p++) {
        for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
            int rc = round_trip(profiles[p], sizes[s]);
            if (rc != 0) {
                return rc;
            }
        }
    }
    return 0;
}
