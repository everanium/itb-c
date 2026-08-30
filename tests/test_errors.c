/* Error-mapping surface: opaque-string relay, closed-adjacent paths,
 * duplicate profile registration (with an 8-entry `innerHashes`
 * constellation). */

#include "test_util.h"

static int run(void)
{
    /* Unknown profile → BAD_INPUT + non-empty diagnostic. */
    itb_pipeline *pipe = NULL;
    itb_status st = itb_pipeline_init("no-such-profile", NULL, &pipe);
    TEST_ASSERT(st == ITB_STATUS_BAD_INPUT,
                "unknown profile: got %d", (int)st);
    TEST_ASSERT(pipe == NULL, "out handle must stay NULL on failure");
    TEST_ASSERT(itb_last_error()[0] != '\0',
                "diagnostic must be non-empty");

    /* Unknown opts key (typoed lowercase s) → BAD_INPUT. */
    itb_opts *bad = itb_opts_new();
    TEST_ASSERT(bad != NULL, "opts alloc");
    st = itb_opts_set(bad, "chunksize", "4096");
    TEST_OK(st, "opts set");
    st = itb_pipeline_init("singlemsg-triple-mac-v1", bad, &pipe);
    TEST_ASSERT(st == ITB_STATUS_BAD_INPUT,
                "unknown opts key: got %d", (int)st);
    itb_opts_free(bad);

    /* An unknown inner-hash name is relayed to Go and rejected there —
     * the binding performs no name validation of its own. */
    itb_opts *hash = itb_opts_new();
    TEST_ASSERT(hash != NULL, "opts alloc");
    st = itb_opts_set(hash, "innerHash", "no-such-hash");
    TEST_OK(st, "opts set");
    st = itb_pipeline_init("singlemsg-triple-mac-v1", hash, &pipe);
    TEST_ASSERT(st != ITB_STATUS_OK, "unknown hash must be rejected");
    itb_opts_free(hash);

    /* RegisterProfile with an 8-entry width-256 innerHashes
     * constellation, layers off. */
    itb_opts *reg = itb_opts_new();
    TEST_ASSERT(reg != NULL, "opts alloc");
    TEST_OK(itb_opts_set(reg, "mode", "singlemsg-nomac"), "set mode");
    TEST_OK(itb_opts_set(reg, "width", "256"), "set width");
    TEST_OK(itb_opts_set(reg, "innerHashes",
                         "blake3,blake2s,areion256,blake2b256,"
                         "chacha20,blake3,blake2s,areion256"),
            "set innerHashes");
    TEST_OK(itb_opts_set(reg, "keyBits", "1024"), "set keyBits");
    TEST_OK(itb_opts_set(reg, "parallaxOn", "false"), "set parallaxOn");
    TEST_OK(itb_opts_set(reg, "wrapperOn", "false"), "set wrapperOn");
    st = itb_register_profile("c-binding-test-mixed", reg);
    TEST_OK(st, "register profile");

    /* The registered profile round-trips. */
    itb_pipeline *sender = NULL;
    st = itb_pipeline_init("c-binding-test-mixed", NULL, &sender);
    TEST_OK(st, "init registered");
    itb_pipeline *receiver = NULL;
    st = itb_pipeline_open("c-binding-test-mixed",
                           itb_pipeline_blob(sender),
                           itb_pipeline_blob_len(sender),
                           NULL, NULL, 0, NULL, 0, &receiver);
    TEST_OK(st, "open registered");
    static const uint8_t plain[] = "custom profile";
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    st = itb_pipeline_encrypt_message(sender, plain, sizeof(plain) - 1,
                                      &wire, &wire_len);
    TEST_OK(st, "encrypt registered");
    uint8_t *back = NULL;
    size_t back_len = 0;
    st = itb_pipeline_decrypt_message(receiver, wire, wire_len,
                                      &back, &back_len);
    TEST_OK(st, "decrypt registered");
    TEST_ASSERT(back_len == sizeof(plain) - 1 &&
                    memcmp(back, plain, back_len) == 0,
                "payload mismatch");
    itb_bytes_free(wire);
    itb_bytes_free(back);
    itb_pipeline_free(receiver);
    itb_pipeline_free(sender);

    /* Duplicate name is a distinct status. */
    st = itb_register_profile("c-binding-test-mixed", reg);
    TEST_ASSERT(st == ITB_STATUS_PROFILE_EXISTS,
                "duplicate profile: got %d", (int)st);
    itb_opts_free(reg);

    /* NULL-safety of the free entries. */
    itb_pipeline_free(NULL);
    itb_stream_free(NULL);
    itb_opts_free(NULL);
    itb_bytes_free(NULL);
    return 0;
}

int main(void)
{
    return run();
}
