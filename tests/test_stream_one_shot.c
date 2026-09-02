/* Round trip through the one-shot stream entries on a Streaming AEAD
 * profile at 256 KiB, wire cross-check against the pump path, and a
 * tampered-wire rejection. */

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

    const size_t size = (size_t)256 * 1024;
    uint8_t *plain = test_payload(size, 0xA5A5A5A5u);
    TEST_ASSERT(plain != NULL, "payload alloc");

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    st = itb_pipeline_encrypt_stream_one_shot(sender, plain, size,
                                              &wire, &wire_len);
    TEST_OK(st, "encrypt one-shot");
    TEST_ASSERT(wire_len > 0, "wire must be non-empty");

    uint8_t *back = NULL;
    size_t back_len = 0;
    st = itb_pipeline_decrypt_stream_one_shot(receiver, wire, wire_len,
                                              &back, &back_len);
    TEST_OK(st, "decrypt one-shot");
    TEST_ASSERT(back_len == size, "length %zu != %zu", back_len, size);
    TEST_ASSERT(memcmp(back, plain, size) == 0, "payload mismatch");

    /* The one-shot wire decodes through the pump path too. */
    uint8_t *back2 = NULL;
    size_t back2_len = 0;
    st = itb_pipeline_decrypt_stream_pump(receiver, wire, wire_len,
                                          &back2, &back2_len);
    TEST_OK(st, "decrypt pump on one-shot wire");
    TEST_ASSERT(back2_len == size, "pump length %zu != %zu", back2_len, size);
    TEST_ASSERT(memcmp(back2, plain, size) == 0, "pump payload mismatch");

    /* A bit flip in authenticated wire content is rejected; the
     * out-parameters stay safe on the rejecting probe. A single flip
     * can land in the container's CSPRNG residue — where the decrypt
     * legitimately completes clean — so successive flip positions are
     * probed until one is rejected. The probe is black-box. */
    int seen_failure = 0;
    for (size_t attempt = 0; attempt < 32 && !seen_failure; attempt++) {
        const size_t flip_pos = (wire_len * 3 / 4 + attempt * 1031) % wire_len;
        wire[flip_pos] ^= 0x01u;
        uint8_t *bad = NULL;
        size_t bad_len = 0;
        st = itb_pipeline_decrypt_stream_one_shot(receiver, wire, wire_len,
                                                  &bad, &bad_len);
        if (st != ITB_STATUS_OK) {
            TEST_ASSERT(bad == NULL && bad_len == 0,
                        "out-parameters must stay NULL / 0 on failure");
            seen_failure = 1;
        } else {
            /* Flip landed in unauthenticated residue. */
            TEST_ASSERT(bad_len == size && memcmp(bad, plain, size) == 0,
                        "residue-flip decrypt must still round-trip");
            itb_bytes_free(bad);
        }
        wire[flip_pos] ^= 0x01u; /* restore for the next probe */
    }
    TEST_ASSERT(seen_failure,
                "no flip position produced an authentication failure");

    free(plain);
    itb_bytes_free(wire);
    itb_bytes_free(back);
    itb_bytes_free(back2);
    itb_pipeline_free(receiver);
    itb_pipeline_free(sender);
    return 0;
}

int main(void)
{
    return run();
}
