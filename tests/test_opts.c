/* Opts builder: rendered query string, percent-encoding, separator
 * placement, NULL handling. Pure builder-surface test — no libitb
 * calls. */

#include "test_util.h"

static int run(void)
{
    /* Empty builder renders the empty query. */
    itb_opts *opts = itb_opts_new();
    TEST_ASSERT(opts != NULL, "opts alloc");
    TEST_ASSERT(strcmp(itb_opts_query(opts), "") == 0, "empty query");

    /* Typical key/value pairs render in insertion order. */
    TEST_OK(itb_opts_set(opts, "chunkSize", "4096"), "set chunkSize");
    TEST_OK(itb_opts_set(opts, "macName", "hmac-blake3"), "set macName");
    TEST_OK(itb_opts_set(opts, "innerHash", "areion512"), "set innerHash");
    TEST_OK(itb_opts_set(opts, "parallaxPalette", "aescmac,chacha20,blake3"),
            "set palette");
    TEST_ASSERT(strcmp(itb_opts_query(opts),
                       "chunkSize=4096&macName=hmac-blake3&"
                       "innerHash=areion512&"
                       "parallaxPalette=aescmac,chacha20,blake3") == 0,
                "query mismatch: %s", itb_opts_query(opts));
    itb_opts_free(opts);

    /* Percent-encoding of reserved bytes in keys and values. */
    opts = itb_opts_new();
    TEST_ASSERT(opts != NULL, "opts alloc");
    TEST_OK(itb_opts_set(opts, "mode", "a b&c=d%"), "set encoded");
    TEST_ASSERT(strcmp(itb_opts_query(opts), "mode=a%20b%26c%3Dd%25") == 0,
                "encoding mismatch: %s", itb_opts_query(opts));
    itb_opts_free(opts);

    /* NULL arguments are rejected without touching the builder. */
    opts = itb_opts_new();
    TEST_ASSERT(opts != NULL, "opts alloc");
    TEST_ASSERT(itb_opts_set(NULL, "k", "v") == ITB_STATUS_BAD_INPUT,
                "NULL builder");
    TEST_ASSERT(itb_opts_set(opts, NULL, "v") == ITB_STATUS_BAD_INPUT,
                "NULL key");
    TEST_ASSERT(itb_opts_set(opts, "k", NULL) == ITB_STATUS_BAD_INPUT,
                "NULL value");
    TEST_ASSERT(strcmp(itb_opts_query(opts), "") == 0,
                "builder must stay untouched");
    TEST_ASSERT(itb_opts_query(NULL) == NULL, "NULL query");
    itb_opts_free(opts);

    /* Growth path: many pairs force several reallocations. */
    opts = itb_opts_new();
    TEST_ASSERT(opts != NULL, "opts alloc");
    for (int i = 0; i < 64; i++) {
        char key[32];
        (void)snprintf(key, sizeof(key), "key%d", i);
        TEST_OK(itb_opts_set(opts, key, "0123456789abcdef"), "growth set");
    }
    TEST_ASSERT(strncmp(itb_opts_query(opts), "key0=0123456789abcdef&", 22)
                    == 0,
                "growth prefix mismatch");
    itb_opts_free(opts);
    return 0;
}

int main(void)
{
    return run();
}
