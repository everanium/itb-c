/*
 * bench_single.c — Easy Mode Single-Ouroboros benchmarks for the C
 * binding.
 *
 * Mirrors the BenchmarkSingle* cohort from itb_ext_test.go for
 * PRF-grade primitives, locked at 1024-bit ITB key width and 16
 * MiB CSPRNG-filled payload. One mixed-primitive variant
 * (itb_encryptor_new_mixed + dedicated lockSeed) covers the
 * Easy Mode Mixed surface alongside the single-primitive grid.
 *
 * Run with:
 *
 *   make bench
 *   ./bench/build/bench_single
 *
 *   ITB_NONCE_BITS=512 ITB_LOCKSEED=1 ITB_LOCKBATCH=1 ./bench/build/bench_single
 *
 *   ITB_NONCE_BITS=512 ITB_LOCKSEED=1 ./bench/build/bench_single
 *
 *   ITB_BENCH_FILTER=blake3_encrypt ./bench/build/bench_single
 *
 * The harness emits one Go-bench-style line per case (name, iters,
 * ns/op, MB/s). See common.h for the supported environment variables
 * and the convergence policy.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "itb.h"

/* Mixed-primitive composition used by the bench_single_mixed_* cases.
 * noise / data / start cycle through the BLAKE family while Areion
 * takes the dedicated lockSeed slot — every name resolves to a 256-bit
 * native hash width so the itb_encryptor_new_mixed width-check passes. */
static const char *const MIXED_NOISE = "blake3";
static const char *const MIXED_DATA  = "blake2s";
static const char *const MIXED_START = "blake2b256";
static const char *const MIXED_LOCK  = "areion256";

#define KEY_BITS      1024
#define MAC_NAME      "hmac-blake3"
#define PAYLOAD_BYTES BENCH_PAYLOAD_16MB

/* One-per-case context owning the encryptor + payload buffer + (for
 * decrypt-side cases) a pre-built ciphertext. The case name is on the
 * bench_case_t struct directly; everything else lives here. */
typedef struct case_ctx {
    itb_encryptor_t *enc;
    uint8_t *payload;
    size_t payload_len;
    uint8_t *ciphertext;
    size_t ciphertext_len;
} case_ctx_t;

/* Cleanup registry — each case's context is freed immediately after
 * that case is measured, via ctx_free_all() at the end of the
 * per-case loop body. */
static case_ctx_t **g_ctx_registry = NULL;
static size_t g_ctx_registry_len = 0;
static size_t g_ctx_registry_cap = 0;

static case_ctx_t *ctx_new(void) {
    case_ctx_t *c = (case_ctx_t *)calloc(1, sizeof(*c));
    if (c == NULL) {
        fprintf(stderr, "ctx_new: out of memory\n");
        abort();
    }
    if (g_ctx_registry_len == g_ctx_registry_cap) {
        size_t new_cap = g_ctx_registry_cap == 0 ? 64 : g_ctx_registry_cap * 2;
        case_ctx_t **next =
            (case_ctx_t **)realloc(g_ctx_registry, new_cap * sizeof(*next));
        if (next == NULL) {
            fprintf(stderr, "ctx_new: registry grow failed\n");
            abort();
        }
        g_ctx_registry = next;
        g_ctx_registry_cap = new_cap;
    }
    g_ctx_registry[g_ctx_registry_len++] = c;
    return c;
}

static void ctx_free_all(void) {
    for (size_t i = 0; i < g_ctx_registry_len; i++) {
        case_ctx_t *c = g_ctx_registry[i];
        if (c == NULL) continue;
        if (c->enc != NULL) {
            itb_encryptor_free(c->enc);
        }
        free(c->payload);
        free(c->ciphertext);
        free(c);
    }
    free(g_ctx_registry);
    g_ctx_registry = NULL;
    g_ctx_registry_len = 0;
    g_ctx_registry_cap = 0;
}

/* Apply the dedicated lockSeed slot when ITB_LOCKSEED is set. Easy
 * Mode auto-couples BitSoup + LockSoup as a side effect, so no
 * separate calls are issued. When ITB_LOCKBATCH is also set, enable the
 * Lock Batch performance Lock Soup mode on the same encryptor. */
static void apply_lockseed_if_requested(itb_encryptor_t *enc) {
    if (env_lock_seed()) {
        itb_status_t s = itb_encryptor_set_lock_seed(enc, 1);
        if (s != ITB_OK) {
            fprintf(stderr, "set_lock_seed(1) failed: %s\n", itb_last_error());
            abort();
        }
    }
    if (env_lock_batch()) {
        itb_status_t s = itb_encryptor_set_lock_batch(enc, 1);
        if (s != ITB_OK) {
            fprintf(stderr, "set_lock_batch(1) failed: %s\n", itb_last_error());
            abort();
        }
    }
}

/* Construct a single-primitive 1024-bit Single-Ouroboros encryptor
 * with HMAC-BLAKE3 authentication. */
static itb_encryptor_t *build_single(const char *primitive) {
    itb_encryptor_t *e = NULL;
    itb_status_t s = itb_encryptor_new(primitive, KEY_BITS, MAC_NAME, 1, &e);
    if (s != ITB_OK || e == NULL) {
        fprintf(stderr, "itb_encryptor_new(%s) failed: %s\n",
                primitive, itb_last_error());
        abort();
    }
    apply_lockseed_if_requested(e);
    return e;
}

/* Construct a mixed-primitive Single-Ouroboros encryptor matching the
 * README Quick Start composition (BLAKE3 noise / BLAKE2s data /
 * BLAKE2b-256 start). The dedicated lockSeed slot is allocated
 * only when ITB_LOCKSEED is set, so the no-LockSeed bench arm measures
 * the plain mixed-primitive cost without the BitSoup + LockSoup
 * auto-couple. */
static itb_encryptor_t *build_mixed_single(void) {
    /* When `prim_l` is non-NULL, itb_encryptor_new_mixed auto-couples
     * BitSoup + LockSoup on construction. When `prim_l` is NULL the
     * encryptor stays in plain mixed mode. */
    const char *prim_l = env_lock_seed() ? MIXED_LOCK : NULL;
    itb_encryptor_t *e = NULL;
    itb_status_t s = itb_encryptor_new_mixed(
        MIXED_NOISE, MIXED_DATA, MIXED_START, prim_l,
        KEY_BITS, MAC_NAME, &e);
    if (s != ITB_OK || e == NULL) {
        fprintf(stderr, "itb_encryptor_new_mixed failed: %s\n",
                itb_last_error());
        abort();
    }
    return e;
}

/* ----- Per-iter callables ------------------------------------------- */

static void run_encrypt(void *ctx, uint64_t iters) {
    case_ctx_t *c = (case_ctx_t *)ctx;
    for (uint64_t i = 0; i < iters; i++) {
        uint8_t *out = NULL;
        size_t out_len = 0;
        itb_status_t s = itb_encryptor_encrypt(
            c->enc, c->payload, c->payload_len, &out, &out_len);
        if (s != ITB_OK) {
            fprintf(stderr, "encrypt failed: %s\n", itb_last_error());
            abort();
        }
        itb_buffer_free(out);
    }
}

static void run_decrypt(void *ctx, uint64_t iters) {
    case_ctx_t *c = (case_ctx_t *)ctx;
    for (uint64_t i = 0; i < iters; i++) {
        uint8_t *out = NULL;
        size_t out_len = 0;
        itb_status_t s = itb_encryptor_decrypt(
            c->enc, c->ciphertext, c->ciphertext_len, &out, &out_len);
        if (s != ITB_OK) {
            fprintf(stderr, "decrypt failed: %s\n", itb_last_error());
            abort();
        }
        itb_buffer_free(out);
    }
}

static void run_encrypt_auth(void *ctx, uint64_t iters) {
    case_ctx_t *c = (case_ctx_t *)ctx;
    for (uint64_t i = 0; i < iters; i++) {
        uint8_t *out = NULL;
        size_t out_len = 0;
        itb_status_t s = itb_encryptor_encrypt_auth(
            c->enc, c->payload, c->payload_len, &out, &out_len);
        if (s != ITB_OK) {
            fprintf(stderr, "encrypt_auth failed: %s\n", itb_last_error());
            abort();
        }
        itb_buffer_free(out);
    }
}

static void run_decrypt_auth(void *ctx, uint64_t iters) {
    case_ctx_t *c = (case_ctx_t *)ctx;
    for (uint64_t i = 0; i < iters; i++) {
        uint8_t *out = NULL;
        size_t out_len = 0;
        itb_status_t s = itb_encryptor_decrypt_auth(
            c->enc, c->ciphertext, c->ciphertext_len, &out, &out_len);
        if (s != ITB_OK) {
            fprintf(stderr, "decrypt_auth failed: %s\n", itb_last_error());
            abort();
        }
        itb_buffer_free(out);
    }
}

/* ----- Case constructors -------------------------------------------- */

/* Encryptor + payload constructed once outside the measured loop;
 * only the encrypt call is timed. */
static bench_case_t make_encrypt_case(char *name, itb_encryptor_t *enc) {
    case_ctx_t *c = ctx_new();
    c->enc = enc;
    c->payload = random_bytes_alloc(PAYLOAD_BYTES);
    if (c->payload == NULL) {
        fprintf(stderr, "make_encrypt_case: payload alloc failed\n");
        abort();
    }
    c->payload_len = PAYLOAD_BYTES;
    bench_case_t bc = { name, run_encrypt, c, PAYLOAD_BYTES };
    return bc;
}

/* Pre-encrypts a single ciphertext outside the measured loop; only
 * the decrypt call is timed. The encryptor's per-instance output cache
 * means the ciphertext bytes returned by encrypt are a freshly
 * malloc'd user-owned copy, ours to keep until ctx_free_all. */
static bench_case_t make_decrypt_case(char *name, itb_encryptor_t *enc) {
    case_ctx_t *c = ctx_new();
    c->enc = enc;
    c->payload = random_bytes_alloc(PAYLOAD_BYTES);
    if (c->payload == NULL) {
        fprintf(stderr, "make_decrypt_case: payload alloc failed\n");
        abort();
    }
    c->payload_len = PAYLOAD_BYTES;
    uint8_t *ct = NULL;
    size_t ct_len = 0;
    itb_status_t s = itb_encryptor_encrypt(enc, c->payload, c->payload_len,
                                            &ct, &ct_len);
    if (s != ITB_OK || ct == NULL) {
        fprintf(stderr, "make_decrypt_case: priming encrypt failed: %s\n",
                itb_last_error());
        abort();
    }
    c->ciphertext = ct;
    c->ciphertext_len = ct_len;
    bench_case_t bc = { name, run_decrypt, c, PAYLOAD_BYTES };
    return bc;
}

static bench_case_t make_encrypt_auth_case(char *name, itb_encryptor_t *enc) {
    case_ctx_t *c = ctx_new();
    c->enc = enc;
    c->payload = random_bytes_alloc(PAYLOAD_BYTES);
    if (c->payload == NULL) {
        fprintf(stderr, "make_encrypt_auth_case: payload alloc failed\n");
        abort();
    }
    c->payload_len = PAYLOAD_BYTES;
    bench_case_t bc = { name, run_encrypt_auth, c, PAYLOAD_BYTES };
    return bc;
}

static bench_case_t make_decrypt_auth_case(char *name, itb_encryptor_t *enc) {
    case_ctx_t *c = ctx_new();
    c->enc = enc;
    c->payload = random_bytes_alloc(PAYLOAD_BYTES);
    if (c->payload == NULL) {
        fprintf(stderr, "make_decrypt_auth_case: payload alloc failed\n");
        abort();
    }
    c->payload_len = PAYLOAD_BYTES;
    uint8_t *ct = NULL;
    size_t ct_len = 0;
    itb_status_t s = itb_encryptor_encrypt_auth(enc, c->payload, c->payload_len,
                                                 &ct, &ct_len);
    if (s != ITB_OK || ct == NULL) {
        fprintf(stderr, "make_decrypt_auth_case: priming encrypt_auth failed: %s\n",
                itb_last_error());
        abort();
    }
    c->ciphertext = ct;
    c->ciphertext_len = ct_len;
    bench_case_t bc = { name, run_decrypt_auth, c, PAYLOAD_BYTES };
    return bc;
}

/* ----- Lazy descriptor ------------------------------------------------
 * Cheap per-case descriptor. No payload or encryptor is allocated here;
 * those are deferred to make_*_case calls in the lazy loop.
 * prim_idx == PRIMITIVES_CANONICAL_LEN signals the "mixed" variant. */

#define OP_ENCRYPT      0
#define OP_DECRYPT      1
#define OP_ENCRYPT_AUTH 2
#define OP_DECRYPT_AUTH 3

typedef struct {
    int    op;       /* OP_* constant above */
    size_t prim_idx; /* PRIMITIVES_CANONICAL index, or PRIMITIVES_CANONICAL_LEN for mixed */
} desc_t;

/* 9 single-primitive entries × 4 ops + 1 mixed entry × 4 ops = 40. */
#define TOTAL_DESCS 40

int main(void) {
    int nonce_bits = env_nonce_bits(128);
    if (itb_set_max_workers(0) != ITB_OK) {
        fprintf(stderr, "itb_set_max_workers(0) failed: %s\n", itb_last_error());
        return 1;
    }
    if (itb_set_nonce_bits(nonce_bits) != ITB_OK) {
        fprintf(stderr, "itb_set_nonce_bits(%d) failed: %s\n",
                nonce_bits, itb_last_error());
        return 1;
    }

    printf("# easy_single primitives=%zu key_bits=%d mac=%s nonce_bits=%d "
           "lockseed=%s workers=auto\n",
           PRIMITIVES_CANONICAL_LEN,
           KEY_BITS,
           MAC_NAME,
           nonce_bits,
           env_lock_seed() ? "on" : "off");
    fflush(stdout);

    /* ----- Build cheap descriptor list (no payload allocs) ------------- */
    desc_t descs[TOTAL_DESCS];
    size_t n_descs = 0;
    static const int OPS[] = {
        OP_ENCRYPT, OP_DECRYPT, OP_ENCRYPT_AUTH, OP_DECRYPT_AUTH
    };
    static const size_t N_OPS = sizeof(OPS) / sizeof(OPS[0]);

    for (size_t i = 0; i < PRIMITIVES_CANONICAL_LEN; i++) {
        for (size_t o = 0; o < N_OPS; o++) {
            descs[n_descs++] = (desc_t){ OPS[o], i };
        }
    }
    /* Mixed-primitive group: prim_idx = PRIMITIVES_CANONICAL_LEN. */
    for (size_t o = 0; o < N_OPS; o++) {
        descs[n_descs++] = (desc_t){ OPS[o], PRIMITIVES_CANONICAL_LEN };
    }

    /* ----- Filter + count ---------------------------------------------- */
    const char *flt = env_filter();
    double min_seconds = env_min_seconds();

    /* Build a temporary name per descriptor to evaluate the filter. */
    size_t sel_idx[TOTAL_DESCS];
    size_t n_sel = 0;
    for (size_t i = 0; i < n_descs; i++) {
        const desc_t *d = &descs[i];
        const char *op_sfx =
            d->op == OP_ENCRYPT      ? "encrypt_16mb"      :
            d->op == OP_DECRYPT      ? "decrypt_16mb"      :
            d->op == OP_ENCRYPT_AUTH ? "encrypt_auth_16mb" :
                                        "decrypt_auth_16mb";
        char tmp[256];
        if (d->prim_idx < PRIMITIVES_CANONICAL_LEN) {
            snprintf(tmp, sizeof(tmp), "bench_single_%s_%dbit_%s",
                     PRIMITIVES_CANONICAL[d->prim_idx], KEY_BITS, op_sfx);
        } else {
            snprintf(tmp, sizeof(tmp), "bench_single_mixed_%dbit_%s",
                     KEY_BITS, op_sfx);
        }
        if (flt == NULL || strstr(tmp, flt) != NULL) {
            sel_idx[n_sel++] = i;
        }
    }

    if (n_sel == 0) {
        fprintf(stderr, "no bench cases match filter %s\n",
                flt == NULL ? "<unset>" : flt);
        return 0;
    }

    printf("# benchmarks=%zu payload_bytes=%zu min_seconds=%g\n",
           n_sel, (size_t)PAYLOAD_BYTES, min_seconds);
    fflush(stdout);

    /* ----- Lazy measure loop ------------------------------------------- */
    for (size_t s = 0; s < n_sel; s++) {
        const desc_t *d = &descs[sel_idx[s]];
        const char *op_sfx =
            d->op == OP_ENCRYPT      ? "encrypt_16mb"      :
            d->op == OP_DECRYPT      ? "decrypt_16mb"      :
            d->op == OP_ENCRYPT_AUTH ? "encrypt_auth_16mb" :
                                        "decrypt_auth_16mb";

        bench_case_t bc;
        if (d->prim_idx < PRIMITIVES_CANONICAL_LEN) {
            const char *prim = PRIMITIVES_CANONICAL[d->prim_idx];
            char *name = bench_strdup_fmt("bench_single_%s_%dbit_%s",
                                          prim, KEY_BITS, op_sfx);
            itb_encryptor_t *enc = build_single(prim);
            switch (d->op) {
            case OP_ENCRYPT:      bc = make_encrypt_case(name, enc);      break;
            case OP_DECRYPT:      bc = make_decrypt_case(name, enc);      break;
            case OP_ENCRYPT_AUTH: bc = make_encrypt_auth_case(name, enc); break;
            default:              bc = make_decrypt_auth_case(name, enc); break;
            }
        } else {
            char *name = bench_strdup_fmt("bench_single_mixed_%dbit_%s",
                                          KEY_BITS, op_sfx);
            itb_encryptor_t *enc = build_mixed_single();
            switch (d->op) {
            case OP_ENCRYPT:      bc = make_encrypt_case(name, enc);      break;
            case OP_DECRYPT:      bc = make_decrypt_case(name, enc);      break;
            case OP_ENCRYPT_AUTH: bc = make_encrypt_auth_case(name, enc); break;
            default:              bc = make_decrypt_auth_case(name, enc); break;
            }
        }

        bench_measure_one(&bc, min_seconds);
        free(bc.name);
        bc.name = NULL;
        ctx_free_all(); /* release encryptor / payload / ciphertext */
    }

    return 0;
}
