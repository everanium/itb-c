/* Persistence surface: save / save_f / load / load_f round trips,
 * inspect, lookup / profiles, max_workers. */

#include <sys/stat.h>
#include <unistd.h>

#include "test_util.h"

static int round_trip(const itb_pipeline *sender, const itb_pipeline *receiver,
                      const char *what)
{
    static const uint8_t plain[] = "persist payload";
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    itb_status st = itb_pipeline_encrypt_message(sender, plain, sizeof(plain) - 1,
                                                 &wire, &wire_len);
    TEST_OK(st, what);
    uint8_t *back = NULL;
    size_t back_len = 0;
    st = itb_pipeline_decrypt_message(receiver, wire, wire_len, &back, &back_len);
    TEST_OK(st, what);
    TEST_ASSERT(back_len == sizeof(plain) - 1 && memcmp(back, plain, back_len) == 0,
                "%s: payload mismatch", what);
    itb_bytes_free(wire);
    itb_bytes_free(back);
    return 0;
}

static int run(void)
{
    itb_pipeline *sender = NULL;
    itb_status st = itb_pipeline_init("singlemsg-triple-mac-v1", NULL, &sender);
    TEST_OK(st, "init");

    /* save → load, save stable, load retains the bytes. */
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    st = itb_pipeline_save(sender, &blob, &blob_len);
    TEST_OK(st, "save");
    uint8_t *again = NULL;
    size_t again_len = 0;
    st = itb_pipeline_save(sender, &again, &again_len);
    TEST_OK(st, "save again");
    TEST_ASSERT(again_len == blob_len && memcmp(again, blob, blob_len) == 0,
                "save must be stable");
    itb_bytes_free(again);

    itb_pipeline *receiver = NULL;
    st = itb_pipeline_load(blob, blob_len, NULL, 0, NULL, 0, &receiver);
    TEST_OK(st, "load");
    if (round_trip(sender, receiver, "in-memory") != 0) {
        return 1;
    }
    st = itb_pipeline_save(receiver, &again, &again_len);
    TEST_OK(st, "save receiver");
    TEST_ASSERT(again_len == blob_len && memcmp(again, blob, blob_len) == 0,
                "load must retain the blob bytes");
    itb_bytes_free(again);
    itb_pipeline_free(receiver);
    receiver = NULL;

    /* load with master overrides == sender rekey. */
    uint8_t perm[32];
    uint8_t wrap[32];
    memset(perm, 0x31, sizeof(perm));
    memset(wrap, 0x32, sizeof(wrap));
    st = itb_pipeline_load(blob, blob_len, perm, sizeof(perm), wrap, sizeof(wrap),
                           &receiver);
    TEST_OK(st, "load with masters");
    st = itb_pipeline_save(receiver, &again, &again_len);
    TEST_OK(st, "save rotated");
    TEST_ASSERT(again_len != blob_len || memcmp(again, blob, blob_len) != 0,
                "master overrides must rotate the blob");
    itb_bytes_free(again);
    st = itb_pipeline_rekey(sender, perm, sizeof(perm), wrap, sizeof(wrap),
                            NULL, NULL);
    TEST_OK(st, "rekey");
    if (round_trip(sender, receiver, "overrides") != 0) {
        return 1;
    }
    itb_pipeline_free(receiver);
    receiver = NULL;

    /* inspect carries the registry recipe plus the blob-only
     * nonce_bits / barrier_fill inspection fields; lookup returns just
     * the recipe. Assert the recipe is present verbatim in inspect and
     * that the two inspection-only fields appear there. Garbage is
     * BAD_INPUT. */
    char *inspected = NULL;
    st = itb_inspect(blob, blob_len, &inspected);
    TEST_OK(st, "inspect");
    char *looked = NULL;
    st = itb_lookup("singlemsg-triple-mac-v1", &looked);
    TEST_OK(st, "lookup");
    /* The recipe JSON returned by lookup is a substring of inspect
     * once the trailing "}" is stripped — inspect adds nonce_bits /
     * barrier_fill after keybits, so match the recipe head + tail. */
    TEST_ASSERT(strstr(inspected, "\"name\":\"singlemsg-triple-mac-v1\"") != NULL,
                "inspect must carry the name");
    TEST_ASSERT(strstr(inspected, "\"mode\":\"singlemsg-mac\"") != NULL,
                "inspect must carry the mode");
    TEST_ASSERT(strstr(looked, "\"name\":\"singlemsg-triple-mac-v1\"") != NULL,
                "lookup must carry the name");
    TEST_ASSERT(strstr(inspected, "\"nonce_bits\":") != NULL,
                "inspect must carry the inspection-only nonce_bits field");
    TEST_ASSERT(strstr(inspected, "\"barrier_fill\":") != NULL,
                "inspect must carry the inspection-only barrier_fill field");
    TEST_ASSERT(strstr(looked, "\"nonce_bits\":") == NULL,
                "lookup must not carry the inspection-only nonce_bits field");
    TEST_ASSERT(strstr(looked, "\"barrier_fill\":") == NULL,
                "lookup must not carry the inspection-only barrier_fill field");
    itb_string_free(inspected);
    itb_string_free(looked);
    inspected = NULL;
    st = itb_inspect((const uint8_t *)"not a blob", 10, &inspected);
    TEST_ASSERT(st == ITB_STATUS_BAD_INPUT, "inspect garbage: got %d", (int)st);
    TEST_ASSERT(inspected == NULL, "json out must stay NULL on failure");
    itb_bytes_free(blob);

    /* profiles lists the shipped catalogue as a JSON string array. */
    char *names = NULL;
    st = itb_profiles(&names);
    TEST_OK(st, "profiles");
    TEST_ASSERT(names[0] == '[', "profiles must be a JSON array: %s", names);
    TEST_ASSERT(strstr(names, "\"singlemsg-triple-mac-v1\"") != NULL,
                "profiles must list the shipped profile: %s", names);
    itb_string_free(names);

    /* save_f → load_f on a temp file (mode 0600), missing file. */
    char path[256];
    (void)snprintf(path, sizeof(path), "/tmp/itb-c-persist-%ld.blob", (long)getpid());
    st = itb_pipeline_save_f(sender, path);
    TEST_OK(st, "save_f");
    struct stat sb;
    TEST_ASSERT(stat(path, &sb) == 0, "saved file must exist");
    TEST_ASSERT((sb.st_mode & 0777) == 0600, "mode %o != 0600", sb.st_mode & 0777);
    st = itb_pipeline_save(sender, &blob, &blob_len);
    TEST_OK(st, "save");
    TEST_ASSERT((size_t)sb.st_size == blob_len, "file size %ld != %zu",
                (long)sb.st_size, blob_len);
    itb_bytes_free(blob);
    st = itb_pipeline_load_f(path, NULL, 0, NULL, 0, &receiver);
    TEST_OK(st, "load_f");
    if (round_trip(sender, receiver, "on-disk") != 0) {
        return 1;
    }
    itb_pipeline_free(receiver);
    receiver = NULL;
    (void)unlink(path);
    st = itb_pipeline_load_f(path, NULL, 0, NULL, 0, &receiver);
    TEST_ASSERT(st == ITB_STATUS_BAD_INPUT, "load_f missing: got %d", (int)st);
    TEST_ASSERT(receiver == NULL, "out handle must stay NULL on failure");

    /* max_workers clamps; closed handle reports TRIPLE_CLOSED. */
    TEST_OK(itb_pipeline_max_workers(sender, 2), "max_workers 2");
    TEST_OK(itb_pipeline_max_workers(sender, -1), "max_workers -1");
    TEST_OK(itb_pipeline_max_workers(sender, 100000), "max_workers 100000");
    st = itb_pipeline_save(sender, &blob, &blob_len);
    TEST_OK(st, "save");
    st = itb_pipeline_load(blob, blob_len, NULL, 0, NULL, 0, &receiver);
    TEST_OK(st, "load");
    itb_bytes_free(blob);
    TEST_OK(itb_pipeline_max_workers(receiver, 1), "max_workers receiver");
    if (round_trip(sender, receiver, "workers") != 0) {
        return 1;
    }
    itb_pipeline_free(receiver);
    itb_pipeline_free(sender);
    return 0;
}

/* Builds a register payload from an inspected profile: the record
 * minus the name and the inspection-only nonce_bits / barrier_fill /
 * container_mode keys, which sit contiguously between keybits and
 * drbg. NULL when the keys are not in that order; caller frees. */
static char *register_payload(const char *inspected)
{
    const char *mode = strstr(inspected, "\"mode\"");
    const char *cut = strstr(inspected, "\"nonce_bits\"");
    const char *drbg = strstr(inspected, "\"drbg\"");
    if (mode == NULL || cut == NULL || drbg == NULL || mode > cut || cut > drbg) {
        return NULL;
    }
    size_t head = (size_t)(cut - mode);
    size_t tail = strlen(drbg);
    char *out = malloc(1 + head + tail + 1);
    if (out == NULL) {
        return NULL;
    }
    out[0] = '{';
    memcpy(out + 1, mode, head);
    memcpy(out + 1 + head, drbg, tail + 1);
    return out;
}

/* The drbg recipe key: an Init under each named fill primitive
 * round-trips through a loaded blob and is reported by inspect; the
 * default leaves the key out of inspect and lookup; an inspected
 * record re-registers under a new name and keeps the key. */
static int run_drbg(void)
{
    static const char *const names[] = {"csprng", "aesitb128"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        itb_opts *opts = itb_opts_new();
        TEST_ASSERT(opts != NULL, "opts alloc");
        TEST_OK(itb_opts_set(opts, "drbg", names[i]), "set drbg");
        itb_pipeline *sender = NULL;
        itb_status st = itb_pipeline_init("singlemsg-triple-mac-v1", opts, &sender);
        TEST_OK(st, "init drbg");
        itb_opts_free(opts);
        itb_pipeline *receiver = NULL;
        st = test_load_from(sender, &receiver);
        TEST_OK(st, "load drbg");
        if (round_trip(sender, receiver, names[i]) != 0) {
            return 1;
        }
        if (round_trip(receiver, sender, names[i]) != 0) {
            return 1;
        }
        uint8_t *blob = NULL;
        size_t blob_len = 0;
        st = itb_pipeline_save(sender, &blob, &blob_len);
        TEST_OK(st, "save drbg");
        char *inspected = NULL;
        st = itb_inspect(blob, blob_len, &inspected);
        TEST_OK(st, "inspect drbg");
        char want[64];
        (void)snprintf(want, sizeof(want), "\"drbg\":\"%s\"", names[i]);
        TEST_ASSERT(strstr(inspected, want) != NULL,
                    "inspect must carry %s: %s", want, inspected);

        if (i == 0) {
            char *payload = register_payload(inspected);
            TEST_ASSERT(payload != NULL, "register payload: %s", inspected);
            st = itb_register("c-binding-test-drbg-copy", payload);
            TEST_OK(st, "register drbg copy");
            free(payload);
            char *looked = NULL;
            st = itb_lookup("c-binding-test-drbg-copy", &looked);
            TEST_OK(st, "lookup drbg copy");
            TEST_ASSERT(strstr(looked, "\"drbg\":\"csprng\"") != NULL,
                        "lookup must keep the drbg key: %s", looked);
            itb_string_free(looked);
        }
        itb_string_free(inspected);
        itb_bytes_free(blob);
        itb_pipeline_free(receiver);
        itb_pipeline_free(sender);
    }

    itb_pipeline *plain = NULL;
    itb_status st = itb_pipeline_init("singlemsg-triple-mac-v1", NULL, &plain);
    TEST_OK(st, "init default");
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    st = itb_pipeline_save(plain, &blob, &blob_len);
    TEST_OK(st, "save default");
    char *inspected = NULL;
    st = itb_inspect(blob, blob_len, &inspected);
    TEST_OK(st, "inspect default");
    TEST_ASSERT(strstr(inspected, "\"drbg\"") == NULL,
                "default inspect must omit drbg: %s", inspected);
    char *looked = NULL;
    st = itb_lookup("singlemsg-triple-mac-v1", &looked);
    TEST_OK(st, "lookup shipped");
    TEST_ASSERT(strstr(looked, "\"drbg\"") == NULL,
                "shipped lookup must omit drbg: %s", looked);
    itb_string_free(looked);
    itb_string_free(inspected);
    itb_bytes_free(blob);
    itb_pipeline_free(plain);
    return 0;
}

int main(void)
{
    if (run() != 0) {
        return 1;
    }
    return run_drbg();
}
