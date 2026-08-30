/* encrypt_stream_pump throughput vs plaintext size (Streaming AEAD
 * profile) at 1 KiB / 64 KiB / 1 MiB / 16 MiB. */

#define _POSIX_C_SOURCE 200809L /* clock_gettime under -std=c11 */

#include <string.h>
#include <sys/random.h>

#include "bench_util.h"

struct stream_ctx {
    itb_pipeline *pipe;
    uint8_t *plain;
    size_t size;
};

struct stream_dec_ctx {
    itb_pipeline *pipe;
    const uint8_t *wire;
    size_t wire_len;
};

static int run_stream_pump(void *raw)
{
    struct stream_ctx *ctx = raw;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    itb_status st = itb_pipeline_encrypt_stream_pump(ctx->pipe, ctx->plain,
                                                     ctx->size, &wire,
                                                     &wire_len);
    if (st != ITB_STATUS_OK) {
        return 1;
    }
    itb_bytes_free(wire);
    return 0;
}

static int run_stream_pump_decrypt(void *raw)
{
    struct stream_dec_ctx *ctx = raw;
    uint8_t *plain = NULL;
    size_t plain_len = 0;
    itb_status st = itb_pipeline_decrypt_stream_pump(ctx->pipe, ctx->wire,
                                                     ctx->wire_len, &plain,
                                                     &plain_len);
    if (st != ITB_STATUS_OK) {
        return 1;
    }
    itb_bytes_free(plain);
    return 0;
}

int main(void)
{
    /* Bench-scale allocation churn leaks Go scratch heap unboundedly
     * without a soft memory cap + aggressive GC; the return values
     * report the previous settings, not an error. */
    (void)itb_set_memory_limit(512LL << 20); /* 512 MiB soft cap */
    (void)itb_set_gc_percent(20);            /* aggressive GC */

    itb_opts *opts = bench_build_opts();
    if (opts == NULL) {
        fprintf(stderr, "bench_stream: opts alloc failed\n");
        return 1;
    }
    itb_pipeline *pipe = NULL;
    itb_status st = itb_pipeline_init(bench_profile_name("streaming-noaead-triple-v1"),
                                      opts, &pipe);
    if (st != ITB_STATUS_OK) {
        fprintf(stderr, "bench_stream: init failed: %s\n", itb_last_error());
        itb_opts_free(opts);
        return 1;
    }
    itb_opts_free(opts);
    bench_header();
    static const size_t sizes[] = {
        (size_t)1 << 20, (size_t)16 << 20, (size_t)64 << 20,
    };
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        uint8_t *plain = malloc(sizes[i]);
        if (plain == NULL) {
            fprintf(stderr, "bench_stream: out of memory\n");
            return 1;
        }
        /* CSPRNG-fill so plaintext content matches the root Go bench
         * (crypto/rand). getrandom returns at most ~33 MiB per call
         * on Linux, so loop until the whole buffer is filled. Not in
         * the timing loop. */
        for (size_t o = 0; o < sizes[i];) {
            ssize_t r = getrandom(plain + o, sizes[i] - o, 0);
            if (r <= 0) {
                fprintf(stderr, "bench_stream: getrandom failed\n");
                return 1;
            }
            o += (size_t)r;
        }
        struct stream_ctx ctx = { pipe, plain, sizes[i] };
        bench_case("stream_pump", sizes[i], run_stream_pump, &ctx);
        /* Pre-encrypt one wire for the decrypt timing loop. */
        uint8_t *dec_wire = NULL;
        size_t dec_wire_len = 0;
        if (itb_pipeline_encrypt_stream_pump(pipe, plain, sizes[i], &dec_wire,
                                             &dec_wire_len) != ITB_STATUS_OK) {
            fprintf(stderr, "bench_stream: dec setup encrypt failed: %s\n",
                    itb_last_error());
            return 1;
        }
        struct stream_dec_ctx dctx = { pipe, dec_wire, dec_wire_len };
        bench_case("stream_pump-dec", sizes[i], run_stream_pump_decrypt, &dctx);
        itb_bytes_free(dec_wire);
        free(plain);
    }
    itb_pipeline_free(pipe);
    return 0;
}
