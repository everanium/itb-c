/* Runtime diagnostics surface: GOMAXPROCS query / set / restore, the
 * heap-profile writer, the pool-counter snapshot and its slot layout,
 * the hash-registry enumeration and the auto DRBG tier report. */

#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <unistd.h>

#include "test_util.h"

static int run(void)
{
    /* GOMAXPROCS: zero queries, a positive value sets and returns the
     * previous one; the query never changes the setting. */
    int32_t orig = itb_set_gomaxprocs(0);
    TEST_ASSERT(orig > 0, "gomaxprocs query returned %d", (int)orig);
    TEST_ASSERT(itb_set_gomaxprocs(-3) == orig, "negative query must not change the value");
    int32_t prev = itb_set_gomaxprocs(orig + 1);
    TEST_ASSERT(prev == orig, "set returned %d, want %d", (int)prev, (int)orig);
    TEST_ASSERT(itb_set_gomaxprocs(0) == orig + 1, "value after set");
    TEST_ASSERT(itb_set_gomaxprocs(orig) == orig + 1, "restore returned the set value");

    /* Heap profile: a real path yields a non-empty file; an empty path
     * with the environment fallback unset is rejected. */
    char path[] = "/tmp/itb-loop-test-heap-XXXXXX";
    int fd = mkstemp(path);
    TEST_ASSERT(fd >= 0, "mkstemp");
    close(fd);
    itb_status st = itb_write_heap_profile(path);
    TEST_OK(st, "write_heap_profile");
    FILE *f = fopen(path, "rb");
    TEST_ASSERT(f != NULL, "profile file missing");
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fclose(f);
    unlink(path);
    TEST_ASSERT(size > 0, "profile file is empty");
    unsetenv("ITB_MEMPROFILE");
    st = itb_write_heap_profile("");
    TEST_ASSERT(st == ITB_STATUS_BAD_INPUT, "empty path: status %d", (int)st);
    st = itb_write_heap_profile(NULL);
    TEST_ASSERT(st == ITB_STATUS_BAD_INPUT, "NULL path: status %d", (int)st);

    /* Pool counters: the length query sizes the buffer, the probe form
     * reports it, a short buffer is refused with the requirement, and
     * a filled buffer carries the tier count in slot 0 under the
     * 1 + 5*T + 8 layout. */
    size_t len = itb_pool_stats_len();
    TEST_ASSERT(len >= 9, "pool stats len %zu", len);
    size_t need = 0;
    st = itb_pool_stats(NULL, 0, &need);
    TEST_ASSERT(st == ITB_STATUS_BUFFER_TOO_SMALL && need == len, "probe: status %d need %zu", (int)st, need);
    int64_t *slots = calloc(len, sizeof(int64_t));
    TEST_ASSERT(slots != NULL, "calloc");
    st = itb_pool_stats(slots, len - 1, &need);
    TEST_ASSERT(st == ITB_STATUS_BUFFER_TOO_SMALL && need == len, "short: status %d need %zu", (int)st, need);
    st = itb_pool_stats(slots, len, &need);
    TEST_OK(st, "pool_stats");
    TEST_ASSERT(need == len, "written %zu != %zu", need, len);
    TEST_ASSERT(slots[0] > 0 && (size_t)(1 + 5 * slots[0] + 8) == len,
                "tier count %lld does not match len %zu", (long long)slots[0], len);
    free(slots);

    /* Hash registry: a JSON array naming the canonical first primitive. */
    char *json = NULL;
    st = itb_hash_names(&json);
    TEST_OK(st, "hash_names");
    TEST_ASSERT(json[0] == '[' && strstr(json, "\"aesitb128\"") != NULL
                    && strstr(json, "\"areion512\"") != NULL,
                "hash names: %s", json);
    itb_string_free(json);

    /* Auto DRBG tier: one of the two fill ciphers, resolved per host. */
    const char *tier = itb_drbg_auto_tier();
    TEST_ASSERT(tier != NULL && (strcmp(tier, "aes-256-ctr") == 0 || strcmp(tier, "chacha20") == 0),
                "drbg auto tier: %s", tier != NULL ? tier : "(null)");
    return 0;
}

int main(void)
{
    return run();
}
