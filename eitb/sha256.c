/*
 * sha256.c — minimal SHA-256 implementation for the eitb verify path.
 *
 * FIPS 180-4 reference, Single Message. Constant-table layout matches
 * the standard; each round folds w[i] into the working variables in
 * the canonical order. The implementation is straight C with no
 * SIMD / AES-NI / SHA-NI intrinsics — used only for byte-level
 * equality verification, not a hot path.
 *
 * Public domain spirit: re-derived from the standard's pseudocode.
 */
#include "sha256.h"

#include <string.h>

static const uint32_t K256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static uint32_t rotr32(uint32_t x, unsigned n)
{
    return (x >> n) | (x << (32u - n));
}

static void sha256_compress(uint32_t state[8], const uint8_t block[64])
{
    uint32_t w[64];
    for (size_t i = 0; i < 16; i++) {
        w[i] = ((uint32_t) block[4 * i] << 24)
             | ((uint32_t) block[4 * i + 1] << 16)
             | ((uint32_t) block[4 * i + 2] << 8)
             |  (uint32_t) block[4 * i + 3];
    }
    for (size_t i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (size_t i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + K256[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void itb_eitb_sha256(const uint8_t *input, size_t len, uint8_t out[ITB_EITB_SHA256_DIGEST_LEN])
{
    uint32_t state[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };

    /* Process full 64-byte blocks. */
    size_t off = 0;
    while (off + 64 <= len) {
        sha256_compress(state, input + off);
        off += 64;
    }

    /* Final padded block(s). */
    uint8_t block[128];
    size_t rem = len - off;
    memcpy(block, input + off, rem);
    block[rem] = 0x80u;
    size_t pad_target;
    if (rem < 56) {
        memset(block + rem + 1, 0, 56 - (rem + 1));
        pad_target = 56;
    } else {
        memset(block + rem + 1, 0, 64 - (rem + 1));
        memset(block + 64, 0, 56);
        pad_target = 56 + 64;
    }
    /* Big-endian length in bits. */
    uint64_t bitlen = (uint64_t) len * 8u;
    block[pad_target + 0] = (uint8_t) (bitlen >> 56);
    block[pad_target + 1] = (uint8_t) (bitlen >> 48);
    block[pad_target + 2] = (uint8_t) (bitlen >> 40);
    block[pad_target + 3] = (uint8_t) (bitlen >> 32);
    block[pad_target + 4] = (uint8_t) (bitlen >> 24);
    block[pad_target + 5] = (uint8_t) (bitlen >> 16);
    block[pad_target + 6] = (uint8_t) (bitlen >> 8);
    block[pad_target + 7] = (uint8_t) (bitlen);

    sha256_compress(state, block);
    if (pad_target == 56 + 64) {
        sha256_compress(state, block + 64);
    }

    for (size_t i = 0; i < 8; i++) {
        out[4 * i + 0] = (uint8_t) (state[i] >> 24);
        out[4 * i + 1] = (uint8_t) (state[i] >> 16);
        out[4 * i + 2] = (uint8_t) (state[i] >> 8);
        out[4 * i + 3] = (uint8_t) (state[i]);
    }
}
