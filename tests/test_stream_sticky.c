/* A decrypt session fed a tampered wire fails with a sticky
 * ITB_STATUS_MAC_FAILURE.
 *
 * A single bit flip can land in the container's CSPRNG residue —
 * over-sized container area that carries no payload — where the
 * decrypt legitimately completes clean. The test therefore probes
 * successive flip positions, each against a fresh session on a fresh
 * copy of the wire, until one lands in authenticated content; the
 * observed failure must be MAC failure and must be sticky. The
 * probe is black-box — no wire-layout knowledge is used. */

#include "test_util.h"

/* Feeds one tampered wire copy through a fresh decrypt session.
 * Returns 0 when the session finishes clean (flip landed in
 * unauthenticated residue), 1 when it failed with the expected
 * sticky MAC failure, and negative on an assertion violation
 * (message already printed). */
static int probe_once(const itb_pipeline *receiver,
                      const uint8_t *wire, size_t wire_len, size_t flip_pos)
{
    uint8_t *tampered = malloc(wire_len);
    if (tampered == NULL) {
        fprintf(stderr, "FAIL: tamper alloc\n");
        return -1;
    }
    memcpy(tampered, wire, wire_len);
    tampered[flip_pos] ^= 0x01;

    itb_stream *sess = NULL;
    itb_status st = itb_pipeline_decrypt_stream_begin(receiver, &sess);
    if (st != ITB_STATUS_OK) {
        fprintf(stderr, "FAIL: begin: %s\n", itb_last_error());
        free(tampered);
        return -1;
    }

    /* The failure may surface on write (chain already failed) or on
     * a later read — either way a read must eventually report it. */
    (void)itb_stream_write(sess, tampered, wire_len);
    (void)itb_stream_end(sess);

    uint8_t buf[4096];
    itb_status first = ITB_STATUS_OK;
    int clean = 0;
    for (;;) {
        size_t n = 0;
        int fin = 0;
        st = itb_stream_read(sess, buf, sizeof(buf), &n, &fin);
        if (st != ITB_STATUS_OK) {
            first = st;
            break;
        }
        if (fin) {
            clean = 1;
            break;
        }
    }
    int rc;
    if (clean) {
        rc = 0; /* flip landed in residue — try the next position */
    } else if (first != ITB_STATUS_MAC_FAILURE) {
        fprintf(stderr, "FAIL: expected MAC failure at pos %zu, got %d (%s)\n",
                flip_pos, (int)first, itb_status_str(first));
        rc = -1;
    } else {
        /* Sticky: a subsequent read reports the same status. */
        size_t n = 0;
        int fin = 0;
        st = itb_stream_read(sess, buf, sizeof(buf), &n, &fin);
        if (st != first) {
            fprintf(stderr, "FAIL: sticky status: got %d, want %d\n",
                    (int)st, (int)first);
            rc = -1;
        } else {
            rc = 1;
        }
    }
    itb_stream_free(sess);
    free(tampered);
    return rc;
}

static int run(void)
{
    itb_pipeline *sender = NULL;
    itb_status st = itb_pipeline_init("streaming-aead-triple-mac-v1", NULL,
                                      &sender);
    TEST_OK(st, "init");

    itb_pipeline *receiver = NULL;
    st = itb_pipeline_open("streaming-aead-triple-mac-v1",
                           itb_pipeline_blob(sender),
                           itb_pipeline_blob_len(sender),
                           NULL, NULL, 0, NULL, 0, &receiver);
    TEST_OK(st, "open");

    const size_t size = 65536;
    uint8_t *plain = malloc(size);
    TEST_ASSERT(plain != NULL, "payload alloc");
    for (size_t i = 0; i < size; i++) {
        plain[i] = (uint8_t)(i % 227);
    }

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    st = itb_pipeline_encrypt_stream_pump(sender, plain, size,
                                          &wire, &wire_len);
    TEST_OK(st, "encrypt pump");
    TEST_ASSERT(wire_len > 0, "wire must be non-empty");

    int seen_failure = 0;
    for (size_t attempt = 0; attempt < 32 && !seen_failure; attempt++) {
        size_t flip_pos = (wire_len * 3 / 4 + attempt * 1031) % wire_len;
        int rc = probe_once(receiver, wire, wire_len, flip_pos);
        if (rc < 0) {
            return 1;
        }
        seen_failure = rc;
    }
    TEST_ASSERT(seen_failure,
                "no flip position produced an authentication failure");

    free(plain);
    itb_bytes_free(wire);
    itb_pipeline_free(receiver);
    itb_pipeline_free(sender);
    return 0;
}

int main(void)
{
    return run();
}
