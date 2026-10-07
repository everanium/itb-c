/*
 * Plaintext content: the payload modes, the seeded per-worker
 * generator, and the buffer fill from the operating-system CSPRNG.
 */

#define _DEFAULT_SOURCE         /* getrandom */
#define _POSIX_C_SOURCE 200809L

#include <string.h>
#include <sys/random.h>

#include "loop.h"

/* Payload mode selector values for the --payload-mode flag.
 *
 *   - fixed: one CSPRNG-generated buffer per worker, held unchanged
 *     for the whole run (the default).
 *   - rotating: the buffer is regenerated before every iteration, so
 *     no two encrypt calls see the same plaintext.
 *   - pattern-zero / pattern-ff: degenerate constant fills (all 0x00 /
 *     all 0xFF) probing minimum-entropy plaintext handling.
 *   - pattern-ascii: a repeating 'A'..'Z' ramp probing low-entropy
 *     structured text. */
static const char *const payload_names[] = {
    "fixed", "rotating", "pattern-zero", "pattern-ff", "pattern-ascii",
};

const char *payload_mode_name(enum payload_mode mode)
{
    return payload_names[mode];
}

int parse_payload_mode(const char *s, enum payload_mode *out)
{
    for (size_t i = 0; i < sizeof(payload_names) / sizeof(payload_names[0]); i++) {
        if (strcmp(s, payload_names[i]) == 0) {
            *out = (enum payload_mode)i;
            return 0;
        }
    }
    return -1;
}

/* Seeded plaintext. The seed makes plaintext content reproducible so
 * a failing iteration can be replayed with the same bytes; it governs
 * nothing else — pipeline keys, nonces and masters stay CSPRNG-drawn,
 * so a seeded run is a reproduction aid and never a security test.
 * Each worker's stream is domain-separated by its id so seeded
 * workers still hold pairwise-distinct buffers under the fixed and
 * rotating modes. The generator is splitmix64: a few lines in any
 * language, which is why it is the one every binding uses. */
uint64_t seed_worker(uint64_t seed, int worker_id)
{
    return seed + (uint64_t)worker_id + 1u;
}

static uint64_t splitmix64(uint64_t *state)
{
    uint64_t z = (*state += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

/* Fills buf from the operating-system CSPRNG. C-specific: getrandom
 * returns at most ~33 MiB per call and may return short on a
 * signal, so the fill loops until every byte is in place. Returns 0
 * on success, -1 on failure. */
int fill_random(uint8_t *buf, size_t n)
{
    size_t off = 0;
    while (off < n) {
        ssize_t r = getrandom(buf + off, n - off, 0);
        if (r <= 0) {
            return -1;
        }
        off += (size_t)r;
    }
    return 0;
}

/* Writes one plaintext buffer according to the payload mode. The
 * fixed and rotating modes draw from the seeded generator when the
 * run is seeded and from the OS CSPRNG otherwise; the pattern modes
 * are deterministic regardless of the seed. Returns 0 on success,
 * -1 when the CSPRNG fails. */
int fill_payload(enum payload_mode mode, bool seeded, uint64_t *rng,
                 uint8_t *buf, size_t n)
{
    switch (mode) {
    case PAYLOAD_FIXED:
    case PAYLOAD_ROTATING:
        if (!seeded) {
            return fill_random(buf, n);
        }
        for (size_t i = 0; i < n; i += 8) {
            uint64_t v = splitmix64(rng);
            size_t take = n - i < 8 ? n - i : 8;
            memcpy(buf + i, &v, take);
        }
        return 0;
    case PAYLOAD_PATTERN_ZERO:
        memset(buf, 0x00, n);
        return 0;
    case PAYLOAD_PATTERN_FF:
        memset(buf, 0xFF, n);
        return 0;
    case PAYLOAD_PATTERN_ASCII:
        for (size_t i = 0; i < n; i++) {
            buf[i] = (uint8_t)('A' + (i % 26));
        }
        return 0;
    }
    return -1;
}
