/*
 * sha256.h — minimal SHA-256 used by the eitb verify path.
 *
 * Self-contained; no libcrypto dependency. The implementation is a
 * clean translation of FIPS 180-4 (Single Message input, fixed
 * 32-byte digest output). The eitb harness only ever computes one
 * digest per plaintext / recovered-plaintext pair, so the simplest
 * one-shot API is the most appropriate.
 *
 * Not a public binding surface — kept under eitb/ so it does not
 * appear in include/itb.h or the libitb_c.a archive.
 */
#ifndef ITB_EITB_SHA256_H
#define ITB_EITB_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define ITB_EITB_SHA256_DIGEST_LEN 32

/* Computes SHA-256(input[0..len)) and writes the 32-byte digest into
 * out. The output buffer must have at least ITB_EITB_SHA256_DIGEST_LEN
 * bytes of capacity. */
void itb_eitb_sha256(const uint8_t *input, size_t len,
                     uint8_t out[ITB_EITB_SHA256_DIGEST_LEN]);

#endif /* ITB_EITB_SHA256_H */
