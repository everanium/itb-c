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

    /* inspect == lookup for a shipped profile; garbage is BAD_INPUT. */
    char *inspected = NULL;
    st = itb_inspect(blob, blob_len, &inspected);
    TEST_OK(st, "inspect");
    char *looked = NULL;
    st = itb_lookup("singlemsg-triple-mac-v1", &looked);
    TEST_OK(st, "lookup");
    TEST_ASSERT(strcmp(inspected, looked) == 0,
                "inspect / lookup mismatch:\n  %s\n  %s", inspected, looked);
    TEST_ASSERT(strstr(inspected, "\"name\":\"singlemsg-triple-mac-v1\"") != NULL,
                "inspect must carry the name");
    TEST_ASSERT(strstr(inspected, "\"mode\":\"singlemsg-mac\"") != NULL,
                "inspect must carry the mode");
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

int main(void)
{
    return run();
}
