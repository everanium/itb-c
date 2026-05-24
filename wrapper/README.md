# ITB Format-Deniability Wrapper — C Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

C-idiomatic surface over the 12 `ITB_Wrap*` / `ITB_Unwrap*` / `ITB_WrapStream*` / `ITB_UnwrapStream*` / `ITB_WrapperKeySize` / `ITB_WrapperNonceSize` exports in `cmd/cshared/main.go`. Wraps an ITB ciphertext under one of nine outer keystream ciphers (Areion-SoEM-256 / Areion-SoEM-512 / SipHash-2-4 / AES-128-CTR / BLAKE2b-256 / BLAKE2b-512 / BLAKE2s / BLAKE3, each in CTR mode, plus ChaCha20 in its native counter mode) so the on-wire bytes carry no ITB-specific format pattern (W / H / container layout for Non-AEAD; 32-byte stream-id prefix + per-chunk metadata for Streaming AEAD). The wrap exists for **format-deniability ONLY** — ITB already provides content-deniability and the AEAD path already provides integrity.

## Threat model

ITB encrypts content into RGBWYOPA pixel containers. The construction provides **content-deniability** unconditionally — no plaintext bit can be extracted from the wire. The wire pattern itself, however, is parseable by an observer who knows the ITB format:

- Non-AEAD path: per-chunk header carries width / height / container layout.
- Streaming AEAD path: a once per-stream 32-byte stream-id prefix plus per-chunk `nonce || W || H || container || flag_byte`.

A passive observer who knows ITB ships with an 8-channel pixel container and a 32-byte stream-id prefix can pattern-match the bytes. The format-deniability wrap hides that surface under a generic outer cipher: Areion-SoEM-256, Areion-SoEM-512, SipHash-2-4, AES-128-CTR, BLAKE2b-256, BLAKE2b-512, BLAKE2s, or BLAKE3 in CTR mode, or ChaCha20 (RFC8439). After wrapping, the wire is `nonce || keystream-XOR(bytestream)` — the same shape used by countless other protocols. An observer sees a small leading nonce followed by pseudorandom-looking bytes; pattern-matching does not distinguish ITB from any other stream cipher payload.

This is **not** a random-oracle indistinguishability claim. It is a "looks like a different well-known cipher" claim. The wrap exists for format-deniability ONLY; ITB already provides confidentiality (content-deniability) and the AEAD path already provides per-stream and per-chunk integrity. The Non-AEAD streaming path has no integrity by design and the wrap does not add any.

## Wrapper API

The C binding exposes the wrap surface in `include/itb.h` under the **Format-deniability wrapper** section. Two flavours of helpers, picked per use case:

| Helper | Wire format | Use case |
|---|---|---|
| `itb_wrap` / `itb_unwrap` | `nonce` + keystream-XOR(blob) | Single Message Encrypt / EncryptAuth output (separately allocated wire buffer) |
| `itb_wrap_in_place` / `itb_unwrap_in_place` | `nonce` separate, body XORed in place | zero-allocation steady state on the hot path; mutates the caller's blob / wire |
| `itb_wrap_stream_writer_*` / `itb_unwrap_stream_reader_*` | `nonce` + keystream-XOR(continuous bytestream) | streaming use — AEAD IO-Driven, or User-Driven Loop where caller-side framing (e.g. per-chunk `u32_LE` length prefixes) is written through the wrap-writer so the framing bytes also pass through the keystream XOR |

The single keystream advances monotonically across all bytes within one wrap session. A fresh CSPRNG nonce is generated per session; emitted once at stream start; never reused across sessions. This is standard CTR mode usage — within one stream, one nonce + counter is correct.

No length-prefix or other framing byte appears in cleartext on the wire in any wrap shape. The User-Driven Loop emits length prefixes through the wrap-writer so they get XORed into the keystream alongside the chunk bodies.

### Cipher selector

```c
typedef enum itb_wrapper_cipher {
    ITB_WRAPPER_CIPHER_AES_128_CTR = 0,
    ITB_WRAPPER_CIPHER_CHACHA20    = 1,
    ITB_WRAPPER_CIPHER_SIPHASH24   = 2,
    ITB_WRAPPER_CIPHER_AREION_256  = 3,
    ITB_WRAPPER_CIPHER_AREION_512  = 4,
    ITB_WRAPPER_CIPHER_BLAKE2B_256 = 5,
    ITB_WRAPPER_CIPHER_BLAKE2B_512 = 6,
    ITB_WRAPPER_CIPHER_BLAKE2S     = 7,
    ITB_WRAPPER_CIPHER_BLAKE3      = 8
} itb_wrapper_cipher_t;

const char *itb_wrapper_cipher_name(itb_wrapper_cipher_t cipher);
```

`itb_wrapper_cipher_name` returns the canonical short name (`"aescmac"` / `"chacha20"` / `"siphash24"` / `"areion256"` / `"areion512"` / `"blake2b256"` / `"blake2b512"` / `"blake2s"` / `"blake3"`) as an interned NUL-terminated C string the caller MUST NOT free.

### Key / nonce sizes

```c
itb_status_t itb_wrapper_key_size(itb_wrapper_cipher_t cipher,   size_t *out_size);
itb_status_t itb_wrapper_nonce_size(itb_wrapper_cipher_t cipher, size_t *out_size);
```

| Cipher | Key | Nonce | Notes |
|---|---|---|---|
| Areion-SoEM-256 in CTR mode | 32 B | 16 B | AES-round-based PRF in CTR mode. Sound under standard PRF assumption. |
| Areion-SoEM-512 in CTR mode | 64 B | 16 B | Wider Areion PRF in CTR mode. Sound under standard PRF assumption. |
| SipHash-2-4 in CTR mode | 16 B | 16 B | `github.com/dchest/siphash` PRF. Custom CTR construction; sound under standard PRF assumption. |
| AES-128-CTR | 16 B | 16 B | stdlib `crypto/aes` + `crypto/cipher.NewCTR`. AES-NI accelerated. |
| BLAKE2b-256 in CTR mode | 32 B | 16 B | Keyed BLAKE2b PRF in CTR mode. Sound under standard PRF assumption. |
| BLAKE2b-512 in CTR mode | 32 B | 16 B | Keyed BLAKE2b PRF (512-bit output) in CTR mode. Sound under standard PRF assumption. |
| BLAKE2s in CTR mode | 32 B | 16 B | Keyed BLAKE2s PRF in CTR mode. Sound under standard PRF assumption. |
| BLAKE3 in CTR mode | 32 B | 16 B | Keyed BLAKE3 PRF in CTR mode. Sound under standard PRF assumption. |
| ChaCha20 (RFC8439) | 32 B | 12 B | `golang.org/x/crypto/chacha20`. No AES-NI dependency. |

### Key generation

```c
itb_status_t itb_wrapper_generate_key(itb_wrapper_cipher_t cipher,
                                      uint8_t **out_key, size_t *out_key_len);
```

Returns a freshly malloc'd CSPRNG key sized for the named cipher. The caller releases the buffer via `itb_buffer_free()`. The CSPRNG reads `/dev/urandom` directly.

## Outer ciphers

| Cipher | Key | Nonce | Notes |
|---|---|---|---|
| Areion-SoEM-256 in CTR mode | 32 B | 16 B | AES-round-based PRF in CTR mode. Sound under standard PRF assumption. |
| Areion-SoEM-512 in CTR mode | 64 B | 16 B | Wider Areion PRF in CTR mode. Sound under standard PRF assumption. |
| SipHash-2-4 in CTR mode | 16 B | 16 B | `github.com/dchest/siphash` PRF. Custom CTR construction; sound under standard PRF assumption. |
| AES-128-CTR | 16 B | 16 B | stdlib `crypto/aes` + `crypto/cipher.NewCTR`. AES-NI accelerated. |
| BLAKE2b-256 in CTR mode | 32 B | 16 B | Keyed BLAKE2b PRF in CTR mode. Sound under standard PRF assumption. |
| BLAKE2b-512 in CTR mode | 32 B | 16 B | Keyed BLAKE2b PRF (512-bit output) in CTR mode. Sound under standard PRF assumption. |
| BLAKE2s in CTR mode | 32 B | 16 B | Keyed BLAKE2s PRF in CTR mode. Sound under standard PRF assumption. |
| BLAKE3 in CTR mode | 32 B | 16 B | Keyed BLAKE3 PRF in CTR mode. Sound under standard PRF assumption. |
| ChaCha20 (RFC8439) | 32 B | 12 B | `golang.org/x/crypto/chacha20`. No AES-NI dependency. |

The SipHash-CTR construction:
- 16-byte SipHash key = wrapper key.
- 16-byte nonce split into `(nonce_hi, nonce_lo)` 64-bit halves.
- Each keystream block: `siphash.Hash128(key, nonce_hi || (nonce_lo XOR counter_LE))` — 16-byte output, XORed with plaintext.
- Counter increments per block; nonce stays fixed for the stream.

## Quick Start

The eitb runner under `bindings/c/eitb/eitb.c` exercises every example × cipher combination end-to-end. Build and run:

```sh
make eitb
./bin/eitb              # 72 PASS, 0 FAIL
./bin/eitb --example aead
./bin/eitb --cipher aes
./bin/eitb -v
```

Eight examples cover the full streaming + Single Message matrix. The C binding has **no Streaming No MAC IO-Driven** examples (there is no `FILE*` / file-like wrapper writer / reader pair for Non-AEAD streaming); the No MAC streaming arm uses the User-Driven Loop only.

### 1. Streaming AEAD Easy (MAC Authenticated, IO-Driven)

ITB Call: `itb_encryptor_stream_encrypt_auth` / `itb_encryptor_stream_decrypt_auth` over a callback-driven memory sink. Wrap shape: one `itb_wrap_stream_writer_t` session over the entire bytestream the inner stream encoder emits.

```c
itb_encryptor_t *enc = NULL;
itb_encryptor_new("areion512", 1024, "hmac-blake3", 1, &enc);

uint8_t *outer_key = NULL; size_t outer_key_len = 0;
itb_wrapper_generate_key(ITB_WRAPPER_CIPHER_AES_128_CTR, &outer_key, &outer_key_len);

/* Sender: encrypt to in-memory sink, then wrap end-to-end. */
grow_t inner = {0};
itb_encryptor_stream_encrypt_auth(enc, read_fn, &pt_src, grow_write, &inner, chunk_size);

uint8_t nonce[16];
itb_wrap_stream_writer_t *ww = NULL;
itb_wrap_stream_writer_new(ITB_WRAPPER_CIPHER_AES_128_CTR, outer_key, outer_key_len,
                           nonce, sizeof(nonce), &ww);
uint8_t *wire = malloc(16 + inner.len);
memcpy(wire, nonce, 16);
itb_wrap_stream_writer_update(ww, inner.data, inner.len, wire + 16, inner.len);
itb_wrap_stream_writer_free(ww);
```

### 2. Streaming AEAD Low-Level (MAC Authenticated, IO-Driven)

ITB Call: `itb_stream_encrypt_auth` / `itb_stream_decrypt_auth` with three explicit `itb_seed_t` handles + an HMAC-BLAKE3 `itb_mac_t`. Wrap shape: as above.

### 3. Streaming Easy (No MAC, User-Driven Loop)

The Go README's "Alternative — User-Driven Loop" pattern: each chunk is one independent `itb_encryptor_encrypt(enc, buf, n, ...)` call. Wrap shape: `itb_wrap_stream_writer_*` driven by a caller loop that emits `u32_LE_len || ct` per chunk through the wrap-writer. Length prefix and chunk body both pass through the keystream XOR — no length appears in cleartext on the wire.

### 4. Streaming Low-Level (No MAC, User-Driven Loop)

Per-chunk `itb_encrypt` / `itb_decrypt` with caller-side framing. Wrap shape as in example 3.

### 5. Easy: Areion-SoEM-512 (No MAC, Single Message)

ITB Call: `itb_encryptor_encrypt(enc, plaintext, ...)` returns one ITB blob. Wrap shape: `itb_wrap_in_place` mutates the blob, returns the per-stream nonce; the caller composes `nonce || mutated-blob` to produce the wire. Receiver `itb_unwrap_in_place` mutates the wire and recovers `wire[nonce_size .. wire_len)` as the plaintext.

```c
uint8_t *encrypted = NULL; size_t encrypted_len = 0;
itb_encryptor_encrypt(enc, plaintext, plaintext_len, &encrypted, &encrypted_len);

uint8_t nonce[16];
itb_wrap_in_place(ITB_WRAPPER_CIPHER_AES_128_CTR, outer_key, outer_key_len,
                  encrypted, encrypted_len, nonce, sizeof(nonce));

size_t wire_len = 16 + encrypted_len;
uint8_t *wire = malloc(wire_len);
memcpy(wire, nonce, 16);
memcpy(wire + 16, encrypted, encrypted_len);

/* Receiver. */
itb_unwrap_in_place(ITB_WRAPPER_CIPHER_AES_128_CTR, outer_key, outer_key_len, wire, wire_len);
uint8_t *pt = NULL; size_t pt_len = 0;
itb_encryptor_decrypt(enc, wire + 16, encrypted_len, &pt, &pt_len);
```

The immutable-input alternative uses `itb_wrap` / `itb_unwrap`, which allocate a fresh wire buffer at the cost of one extra malloc per call. The eitb runner exercises both via commented alternatives.

### 6. Easy: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated, Single Message)

ITB Call: `itb_encryptor_encrypt_auth` / `itb_encryptor_decrypt_auth`. Wrap shape: as in example 5. The ITB-internal 32-byte MAC tag remains inside the RGBWYOPA container; outer cipher is format-deniability only.

### 7. Low-Level: Areion-SoEM-512 (No MAC, Single Message)

ITB Call: `itb_encrypt(noise, data, start, plaintext, ...)` / `itb_decrypt(...)` with three explicit `itb_seed_t` handles built from `itb_seed_new("areion512", 2048, ...)`. Wrap shape as in example 5.

### 8. Low-Level: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated, Single Message)

ITB Call: `itb_encrypt_auth` / `itb_decrypt_auth` with the MAC closure constructed via `itb_mac_new("hmac-blake3", mac_key, 32, ...)`. Wrap shape as in example 5.

## Verification matrix

Every example × cipher combination round-trips against random plaintext (1 KiB for Single Message, 64 KiB for streaming) with sha256 byte-equality. Sample run:

```
[PASS] aead-easy-io               + areion256   pt=65536 wire=90016
[PASS] aead-easy-io               + areion512   pt=65536 wire=90016
[PASS] aead-easy-io               + siphash24   pt=65536 wire=90016
[PASS] aead-easy-io               + aescmac    pt=65536 wire=90016
[PASS] aead-easy-io               + blake2b256   pt=65536 wire=90016
[PASS] aead-easy-io               + blake2b512   pt=65536 wire=90016
[PASS] aead-easy-io               + blake2s    pt=65536 wire=90016
[PASS] aead-easy-io               + blake3     pt=65536 wire=90016
[PASS] aead-easy-io               + chacha20   pt=65536 wire=90012
...
[PASS] message-lowlevel-auth      + areion256   pt=1024 wire=8228
[PASS] message-lowlevel-auth      + areion512   pt=1024 wire=8228
[PASS] message-lowlevel-auth      + siphash24   pt=1024 wire=8228
[PASS] message-lowlevel-auth      + aescmac    pt=1024 wire=8228
[PASS] message-lowlevel-auth      + blake2b256   pt=1024 wire=8228
[PASS] message-lowlevel-auth      + blake2b512   pt=1024 wire=8228
[PASS] message-lowlevel-auth      + blake2s    pt=1024 wire=8228
[PASS] message-lowlevel-auth      + blake3     pt=1024 wire=8228
[PASS] message-lowlevel-auth      + chacha20   pt=1024 wire=8224

=== Summary: 72 PASS, 0 FAIL ===
```

The wire-byte difference between cipher columns is exactly the per-stream nonce-size delta (12 bytes for ChaCha20, 16 bytes for every other outer cipher); the User-Driven Loop variants additionally include 4 bytes of keystream-XORed length prefix per chunk.

## Performance

Bench numbers across Single Ouroboros and Triple Ouroboros, message and streaming, encrypt and decrypt (split sub-benches) are tracked in [BENCH.md](BENCH.md). Total sub-bench count: 102 (6 wrapper only round-trip + 24 Message Single + 24 Message Triple + 24 Streaming Single + 24 Streaming Triple).

## Notes on outer cipher key management

The wrapper itself does not address outer key distribution; the eitb runner generates a fresh CSPRNG outer key per run for self-test purposes. In a real deployment the outer key is shared out-of-band (or derived via a separate key-exchange step) and is independent of the ITB seed material. The ITB state blob already carries the inner cipher's keying material; the outer key is the additional piece both endpoints need.

The outer key MAY be reused across many streams provided each stream uses a fresh CSPRNG nonce — this is the standard CTR mode safety contract. The wrapper helpers always generate a fresh nonce internally, so caller-side discipline is reduced to "do not reuse the same `(key, nonce)` across distinct streams" — a contract the helper enforces by construction.

## Threading

The Single Message `itb_wrap` / `itb_unwrap` / `itb_wrap_in_place` / `itb_unwrap_in_place` are thread-safe: each call constructs an outer cipher session of its own and the libitb keystream constructor draws a fresh CSPRNG nonce per call. The streaming `itb_wrap_stream_writer_t` / `itb_unwrap_stream_reader_t` handles are single-feeder — every `_update` call advances the underlying keystream counter; concurrent `_update` calls on the same handle race. Distinct handles run independently.

## What this is not

- Not an integrity layer. The outer cipher is unauthenticated by design — adding a MAC at this layer would defeat the format-deniability goal (the resulting wire would pattern-match an AEAD construction's tag-bearing format, not a generic stream cipher). Use the ITB AEAD path when integrity is required.
- Not a substitute for ITB's content-deniability. ITB still provides the unconditional content-deniability; the wrap adds format-deniability on top.
