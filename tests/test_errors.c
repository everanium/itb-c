/* Error-mapping surface: opaque-string relay, unknown profile,
 * closed-adjacent paths, duplicate profile registration (with an
 * 8-entry `hashes` constellation). */

#include "test_util.h"

static int run(void)
{
    /* Unknown profile → UNKNOWN_PROFILE + non-empty diagnostic, on
     * init and on lookup alike. */
    itb_pipeline *pipe = NULL;
    itb_status st = itb_pipeline_init("no-such-profile", NULL, &pipe);
    TEST_ASSERT(st == ITB_STATUS_UNKNOWN_PROFILE,
                "unknown profile: got %d", (int)st);
    TEST_ASSERT(pipe == NULL, "out handle must stay NULL on failure");
    TEST_ASSERT(itb_last_error()[0] != '\0',
                "diagnostic must be non-empty");
    char *json = NULL;
    st = itb_lookup("no-such-profile", &json);
    TEST_ASSERT(st == ITB_STATUS_UNKNOWN_PROFILE,
                "lookup unknown profile: got %d", (int)st);
    TEST_ASSERT(json == NULL, "json out must stay NULL on failure");

    /* A negative maxWorkers opts value is clamped, not rejected. */
    itb_opts *neg = itb_opts_new();
    TEST_ASSERT(neg != NULL, "opts alloc");
    TEST_OK(itb_opts_set(neg, "maxWorkers", "-1"), "opts set");
    st = itb_pipeline_init("singlemsg-triple-mac-v1", neg, &pipe);
    TEST_OK(st, "init maxWorkers=-1");
    itb_pipeline_free(pipe);
    pipe = NULL;
    itb_opts_free(neg);

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

    /* Register with an 8-entry width-256 hashes constellation, layers
     * off. The record is a profile JSON object. */
    static const char reg[] =
        "{\"mode\":\"singlemsg-nomac\",\"width\":256,"
        "\"hashes\":[\"blake3\",\"blake2s\",\"areion256\",\"blake2b256\","
        "\"chacha20\",\"blake3\",\"blake2s\",\"areion256\"],"
        "\"keybits\":1024,\"wrapper\":false,\"parallax\":false}";
    st = itb_register("c-binding-test-mixed", reg);
    TEST_OK(st, "register profile");

    /* The registered record reads back with its name filled in. */
    st = itb_lookup("c-binding-test-mixed", &json);
    TEST_OK(st, "lookup registered");
    TEST_ASSERT(strstr(json, "\"name\":\"c-binding-test-mixed\"") != NULL,
                "lookup must carry the name: %s", json);
    TEST_ASSERT(strstr(json, "\"hashes\":[\"blake3\",\"blake2s\"") != NULL,
                "lookup must carry the hashes: %s", json);
    itb_string_free(json);
    json = NULL;

    /* A non-empty name inside the record must equal the argument. */
    st = itb_register("c-binding-test-mismatch",
                      "{\"name\":\"other\",\"mode\":\"singlemsg-nomac\","
                      "\"width\":512,\"hash\":\"areion512\",\"keybits\":1024,"
                      "\"wrapper\":false,\"parallax\":false}");
    TEST_ASSERT(st == ITB_STATUS_BAD_INPUT,
                "name mismatch: got %d", (int)st);

    /* The registered profile round-trips. */
    itb_pipeline *sender = NULL;
    st = itb_pipeline_init("c-binding-test-mixed", NULL, &sender);
    TEST_OK(st, "init registered");
    itb_pipeline *receiver = NULL;
    st = test_load_from(sender, &receiver);
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
    st = itb_register("c-binding-test-mixed", reg);
    TEST_ASSERT(st == ITB_STATUS_PROFILE_EXISTS,
                "duplicate profile: got %d", (int)st);

    /* Closed-adjacent paths: NULL pipe on the new entries. */
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    TEST_ASSERT(itb_pipeline_save(NULL, &blob, &blob_len) == ITB_STATUS_BAD_INPUT,
                "save NULL pipe");
    TEST_ASSERT(itb_pipeline_max_workers(NULL, 2) == ITB_STATUS_BAD_INPUT,
                "max_workers NULL pipe");
    TEST_ASSERT(itb_inspect(NULL, 0, &json) == ITB_STATUS_BAD_INPUT,
                "inspect NULL blob");

    /* NULL-safety of the free entries. */
    itb_pipeline_free(NULL);
    itb_stream_free(NULL);
    itb_opts_free(NULL);
    itb_bytes_free(NULL);
    itb_string_free(NULL);
    return 0;
}

int main(void)
{
    return run();
}
