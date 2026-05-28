# ITB C Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

C17 wrapper over the libitb shared library (`cmd/cshared`). The binding
ships one public header (`include/itb.h`) plus a static archive
(`build/libitb_c.a`); consumer applications compile against the header
and link `-litb_c -litb` so the dynamic loader resolves the underlying
`ITB_*` exports against `libitb.so` at process start. No `dlopen`, no
runtime FFI shim — every `ITB_*` symbol is bound at link time.

**Path placeholder.** `<itb>` denotes the path to the local ITB
repository checkout (or this binding's mirror clone) — for example,
`/home/you/go/src/itb` or `~/projects/itb-c`. Substitute the literal
token in the recipes below; shell does not expand it.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go go-tools gcc clang make pkgconf check
```

`gcc` is the reference compiler; `clang` is exercised by the same
Makefile (`CC=clang make`). `pkgconf` resolves `pkg-config --cflags
check` for the test runner. `check` is the unit-testing framework used
by `tests/test_*.c` — only required for `make tests` / `./run_tests.sh`,
not for consumer applications that link `-litb_c`.

## Build the shared library

The convenience driver `bindings/c/build.sh` builds `libitb.so` plus
the C binding's static archive in one step. Run it from anywhere:

```bash
./bindings/c/build.sh
```

The driver expands to two underlying steps — building libitb from the
repo root, then `make` on the binding side. Equivalent manual
invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
cd bindings/c && make
```

(macOS produces `libitb.dylib` under `dist/darwin-<arch>/`,
Windows produces `libitb.dll` under `dist/windows-<arch>/`.)

### Compiler selection

Both `gcc` and `clang` are exercised by the binding's CI matrix; both
accept the source unchanged at `-std=c17 -Wall -Wextra -Wpedantic`:

```bash
CC=gcc   make           # reference compiler
CC=clang make           # LLVM-backed compiler
```

The Makefile ships with extra-strict warning flags
(`-Wshadow -Wconversion -Wsign-conversion -Wstrict-prototypes
-Wmissing-prototypes`) on top of the standard `-Wall -Wextra
-Wpedantic` baseline. The full library + tests + bench harness build
clean under both compilers at this flag set.

## Add to a C / C++ project

Compile against the public header and link the static archive plus the
underlying `libitb.so`:

```bash
cc -std=c17 -I/path/to/bindings/c/include myapp.c \
    -L/path/to/bindings/c/build -litb_c \
    -L/path/to/dist/linux-amd64 -Wl,-rpath,/path/to/dist/linux-amd64 \
    -litb
```

The header is C++-aware (`extern "C"` block guarded by
`__cplusplus`), so the same archive serves C and C++ consumers without
a separate wrapper.

## Library lookup order

1. `LD_LIBRARY_PATH` resolved at process startup. The test runner
   inherits the embedded RPATH and does not export it.
2. The `rpath` baked into the produced binary at link time
   (`-Wl,-rpath,../../dist/linux-amd64`). Installed binaries find
   `libitb` without `LD_LIBRARY_PATH`.
3. System loader path (`ld.so.cache`, `DYLD_LIBRARY_PATH`, `PATH`).

## Memory

Two process-wide knobs constrain Go runtime arena pacing. Both readable at libitb load time via env vars:

- `ITB_GOMEMLIMIT=512MiB` — soft memory limit in bytes; supports `B` / `KiB` / `MiB` / `GiB` / `TiB` suffixes.
- `ITB_GOGC=20` — GC trigger percentage; default `100`, lower triggers GC more aggressively.

Programmatic setters override env-set values at any time. Pass `-1` to either setter to query the current value without changing it.

```c
itb_set_memory_limit(512LL << 20);
itb_set_gc_percent(20);
```

## Tests

```bash
cd bindings/c
make tests        # compile every test binary
make test         # compile + run via ./run_tests.sh
./run_tests.sh
```

The harness compiles every `tests/test_*.c` to its own standalone
executable under `tests/build/` and runs each in turn. Per-process
isolation gives every test a fresh libitb global state without needing
an in-process serial lock. The 30 test files mirror the cross-binding
coverage: Single + Triple Ouroboros, mixed primitives, authenticated
paths, blob round-trip, streaming chunked I/O, error paths, lockSeed
lifecycle, persistence, per-instance configuration overrides.

Override the compiler via the `CC` environment variable:

```bash
CC=clang ./bindings/c/run_tests.sh
```

Each test file is compiled to its own standalone executable under
`tests/build/` and linked against `build/libitb_c.a` plus `libitb.so`
plus the system [Check](https://libcheck.github.io/check/) unit-testing
framework. Per-process isolation gives every test a fresh libitb global
state.

## Benchmarks

A custom Go-bench-style harness lives under `bench/` and covers the
four ops (`encrypt`, `decrypt`, `encrypt_auth`, `decrypt_auth`) across
PRF-grade primitives plus one mixed-primitive variant for
both Single and Triple Ouroboros at 1024-bit ITB key width and 16 MiB
payload. See [`bench/README.md`](bench/README.md) for invocation /
environment variables / output format and [`bench/BENCH.md`](bench/BENCH.md)
for recorded throughput results across the canonical pass matrix.

The four-pass canonical sweep that fills `bench/BENCH.md` is driven by
the wrapper script in the binding root:

```bash
cd bindings/c
make bench
./run_bench.sh                  # full 4-pass canonical sweep
```

## Streaming AEAD

**Streaming AEAD** authenticates a chunked stream end-to-end while
preserving the deniability of the per-chunk MAC-Inside-Encrypt
container. Each chunk's MAC binds the encrypted payload to a 32-byte
CSPRNG stream anchor (written as a once-per-stream wire prefix), the
cumulative pixel offset of preceding chunks, and a final-flag bit —
defending against chunk reorder, replay within or across streams
sharing the PRF / MAC key, silent mid-stream drop, and truncate-tail.
The wire format adds 32 bytes of stream prefix plus one byte of
encrypted trailing flag per chunk; no externally visible MAC tag.

**Easy Mode:**

`itb_encryptor_stream_encrypt_auth` consumes plaintext via a `read_fn`
callback and emits the on-wire transcript via a `write_fn` callback.
Both callbacks receive an opaque `user_ctx` pointer that the binding
does not interpret — the example wires it to a `FILE *` opened via
`fopen`, and the callbacks perform `fread` / `fwrite` against the
file. The MAC key is allocated CSPRNG-fresh inside the encryptor at
constructor time.

```c
#include "itb.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHUNK_SIZE  ((size_t)16 * 1024 * 1024)

static int file_read_fn(void *ctx, void *buf, size_t cap, size_t *out_n) {
    *out_n = fread(buf, 1, cap, (FILE *) ctx);
    return 0;
}

static int file_write_fn(void *ctx, const void *buf, size_t n) {
    return (fwrite(buf, 1, n, (FILE *) ctx) == n) ? 0 : -1;
}

/* In-memory grow sink — the inner ITB stream lands here so the wrap-
 * stream writer can XOR the whole transcript through one keystream
 * session before it reaches the wire. */
typedef struct { uint8_t *data; size_t len, cap; } grow_t;
static int grow_write(void *ctx, const void *buf, size_t n) {
    grow_t *g = ctx;
    if (g->len + n > g->cap) {
        size_t nc = g->cap ? g->cap * 2 : 4096;
        while (nc < g->len + n) nc *= 2;
        uint8_t *p = realloc(g->data, nc);
        if (!p) return 1;
        g->data = p; g->cap = nc;
    }
    memcpy(g->data + g->len, buf, n); g->len += n;
    return 0;
}

typedef struct { const uint8_t *p; size_t len, pos; } mread_t;
static int mread_read(void *ctx, void *buf, size_t cap, size_t *out_n) {
    mread_t *m = ctx;
    size_t take = m->len - m->pos; if (take > cap) take = cap;
    memcpy(buf, m->p + m->pos, take); m->pos += take; *out_n = take;
    return 0;
}

itb_encryptor_t *enc = NULL;
itb_encryptor_new("areion512", 1024, "hmac-blake3", 1, &enc);

/* Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived. */
uint8_t *outerKey = NULL; size_t outerKey_len = 0;
itb_wrapper_generate_key(ITB_WRAPPER_CIPHER_AES_128_CTR,
                         &outerKey, &outerKey_len);
// itb_wrapper_derive_key(ITB_WRAPPER_CIPHER_AES_128_CTR, master, master_len,
//                        &outerKey, &outerKey_len);

/* Sender — collect the inner ITB stream in memory. */
grow_t inner = {0};
FILE *fin = fopen("/tmp/64mb.src", "rb");
itb_encryptor_stream_encrypt_auth(enc, file_read_fn, fin,
                                  grow_write, &inner, CHUNK_SIZE);
fclose(fin);

/* Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case). */
uint8_t nonce_buf[16] = {0};
itb_wrap_stream_writer_t *ww = NULL;
itb_wrap_stream_writer_new(ITB_WRAPPER_CIPHER_AES_128_CTR,
                           outerKey, outerKey_len,
                           nonce_buf, sizeof nonce_buf, &ww);
size_t nlen = 0;
itb_wrapper_nonce_size(ITB_WRAPPER_CIPHER_AES_128_CTR, &nlen);

uint8_t *wire_body = (uint8_t *) malloc(inner.len);
itb_wrap_stream_writer_update(ww, inner.data, inner.len, wire_body, inner.len);
itb_wrap_stream_writer_free(ww);

FILE *fout = fopen("/tmp/64mb.enc", "wb");
fwrite(nonce_buf, 1, nlen, fout);
fwrite(wire_body, 1, inner.len, fout);
fclose(fout);
free(wire_body);
free(inner.data);

/* Receiver — strip nonce prefix, unwrap, feed to decrypt_auth. */
fin = fopen("/tmp/64mb.enc", "rb");
uint8_t wire_nonce[16] = {0};
fread(wire_nonce, 1, nlen, fin);
itb_unwrap_stream_reader_t *ur = NULL;
itb_unwrap_stream_reader_new(ITB_WRAPPER_CIPHER_AES_128_CTR,
                             outerKey, outerKey_len,
                             wire_nonce, nlen, &ur);

grow_t inner2 = {0};
{
    uint8_t buf[1 << 16], obuf[1 << 16]; size_t n;
    while ((n = fread(buf, 1, sizeof buf, fin)) > 0) {
        itb_unwrap_stream_reader_update(ur, buf, n, obuf, sizeof obuf);
        grow_write(&inner2, obuf, n);
    }
}
fclose(fin);
itb_unwrap_stream_reader_free(ur);

mread_t inner_src = { inner2.data, inner2.len, 0 };
fout = fopen("/tmp/64mb.dst", "wb");
itb_encryptor_stream_decrypt_auth(enc, mread_read, &inner_src,
                                  file_write_fn, fout, CHUNK_SIZE);
fclose(fout);
free(inner2.data);
itb_buffer_free(outerKey);
itb_encryptor_free(enc);
```

**Build + run:**

```sh
gcc -O2 -Wall -o main main.c \
    -I <itb>/bindings/c/include \
    <itb>/bindings/c/build/libitb_c.a \
    -L <itb>/dist/linux-amd64 -litb \
    -Wl,-rpath,<itb>/dist/linux-amd64 \
    -lpthread -ldl -lm
./main
```

**Output (verified):**

```
Easy Mode src sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
Easy Mode dst sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
[OK] Easy Mode: 64 MiB roundtrip via stream-auth verified
```

---

**Low-Level Mode:**

Free functions `itb_stream_encrypt_auth` / `itb_stream_decrypt_auth`
take three `itb_seed_t *` handles plus an `itb_mac_t *` (constructed
with a 32-byte key from `/dev/urandom`) and stream through the same
chunked-AEAD construction. The same `read_fn` / `write_fn` callback
shape applies as in Easy Mode.

```c
itb_seed_t *noise = NULL, *data = NULL, *start = NULL;
itb_mac_t  *mac = NULL;
unsigned char mac_key[32];                 /* fill from /dev/urandom */

itb_seed_new("areion512", 1024, &noise);
itb_seed_new("areion512", 1024, &data);
itb_seed_new("areion512", 1024, &start);
itb_mac_new ("hmac-blake3", mac_key, sizeof mac_key, &mac);

/* Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived. */
uint8_t *outerKey = NULL; size_t outerKey_len = 0;
itb_wrapper_generate_key(ITB_WRAPPER_CIPHER_AES_128_CTR,
                         &outerKey, &outerKey_len);
// itb_wrapper_derive_key(ITB_WRAPPER_CIPHER_AES_128_CTR, master, master_len,
//                        &outerKey, &outerKey_len);

/* Collect the inner ITB stream in memory. */
grow_t inner = {0};
FILE *fin = fopen("/tmp/64mb.src", "rb");
itb_stream_encrypt_auth(noise, data, start, mac,
    file_read_fn, fin, grow_write, &inner, CHUNK_SIZE);
fclose(fin);

/* Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case). */
uint8_t nonce_buf[16] = {0};
itb_wrap_stream_writer_t *ww = NULL;
itb_wrap_stream_writer_new(ITB_WRAPPER_CIPHER_AES_128_CTR,
                           outerKey, outerKey_len,
                           nonce_buf, sizeof nonce_buf, &ww);
size_t nlen = 0;
itb_wrapper_nonce_size(ITB_WRAPPER_CIPHER_AES_128_CTR, &nlen);

uint8_t *wire_body = (uint8_t *) malloc(inner.len);
itb_wrap_stream_writer_update(ww, inner.data, inner.len, wire_body, inner.len);
itb_wrap_stream_writer_free(ww);

FILE *fout = fopen("/tmp/64mb.enc", "wb");
fwrite(nonce_buf, 1, nlen, fout);
fwrite(wire_body, 1, inner.len, fout);
fclose(fout);
free(wire_body);
free(inner.data);
itb_buffer_free(outerKey);

itb_mac_free(mac);
itb_seed_free(noise); itb_seed_free(data); itb_seed_free(start);
```

**Build + run:**

```sh
gcc -O2 -Wall -o main main.c \
    -I <itb>/bindings/c/include \
    <itb>/bindings/c/build/libitb_c.a \
    -L <itb>/dist/linux-amd64 -litb \
    -Wl,-rpath,<itb>/dist/linux-amd64 \
    -lpthread -ldl -lm
./main
```

**Output (verified):**

```
Low-Level src sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
Low-Level dst sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
[OK] Low-Level Mode: 64 MiB roundtrip via stream-auth verified
```

Linking pulls in both the static C-binding archive
(`build/libitb_c.a`, the C wrapper layer that exposes
`itb_encryptor_*` / `itb_seed_*` / `itb_mac_*` / `itb_*_stream_*` to
user code) AND the shared Go-built library (`-litb` resolved against
`dist/<os>-<arch>/libitb.so`, which carries the raw `ITB_*` ABI). An
rpath embedded into the binary lets it find `libitb.so` at runtime
without `LD_LIBRARY_PATH`.

## Quick Start — `itb_encryptor_t` + HMAC-BLAKE3 (MAC Authenticated)

The high-level Easy Mode encryptor (mirroring the
`github.com/everanium/itb/easy` Go sub-package) replaces the seven-line
setup ceremony of the lower-level seed / `itb_encrypt` / `itb_decrypt`
path with one constructor call: the encryptor allocates its own three
(Single) or seven (Triple) seeds plus MAC closure, snapshots the global
configuration into a per-instance Config, and exposes setters that
mutate only its own state without touching the process-wide
`itb_set_*` accessors. Two encryptors with different settings can run
side-by-side without cross-contamination.

The MAC primitive is bound at construction time — the third constructor
argument selects one of the registry names (`hmac-blake3` —
recommended default, `hmac-sha256`, `kmac256`). The encryptor allocates
a fresh 32-byte CSPRNG MAC key alongside the per-seed PRF keys;
`itb_encryptor_export` carries all of them in a single JSON blob. On
the receiver side, `itb_encryptor_import(dec, blob, blob_len)` restores
the MAC key together with the seeds, so the encrypt-today /
decrypt-tomorrow flow is one method call per side.

When the `mac_name` argument is `NULL` or the empty string `""` the
binding picks `hmac-blake3` rather than forwarding NULL through to
libitb's own default — HMAC-BLAKE3 measures the lightest
authenticated-mode overhead across the Easy Mode bench surface.

```c
/* Sender */

#include <itb.h>
#include <stdio.h>
#include <string.h>

/* Per-instance configuration — mutates only this encryptor's
 * Config. Two encryptors built side-by-side carry independent
 * settings; process-wide itb_set_* accessors are NOT consulted
 * after construction. mode = 1 = Single Ouroboros (3 seeds);
 * mode = 3 = Triple Ouroboros (7 seeds). */
itb_encryptor_t *enc = NULL;
itb_encryptor_new("areion512", 2048, "hmac-blake3", 1, &enc);

itb_encryptor_set_nonce_bits(enc, 512);    /* 512-bit nonce (default: 128-bit) */
itb_encryptor_set_barrier_fill(enc, 4);    /* CSPRNG fill margin (default: 1, valid: 1, 2, 4, 8, 16, 32) */
itb_encryptor_set_bit_soup(enc, 1);        /* optional bit-level split ("bit-soup"; default: 0 = byte-level) */
                                           /* auto-enabled for Single Ouroboros if set_lock_soup(1) is on */
itb_encryptor_set_lock_soup(enc, 1);       /* optional Insane Interlocked Mode: per-chunk PRF-keyed
                                            * bit-permutation overlay on top of bit-soup;
                                            * auto-enabled for Single Ouroboros if set_bit_soup(1) is on */
itb_encryptor_set_lock_batch(enc, 1);      /* Lock Batch is the performance Lock Soup mode: recommended
                                            * in every case when the configured hash is PRF-grade, since
                                            * security is preserved under the PRF assumption while
                                            * throughput rises. Symmetric option — set identically on
                                            * the encrypt and decrypt sides. */

/* itb_encryptor_set_lock_seed(enc, 1);    optional dedicated lockSeed for the bit-permutation
                                           derivation channel — separates that PRF's keying
                                           material from the noiseSeed-driven noise-injection
                                           channel; auto-couples set_lock_soup(1) +
                                           set_bit_soup(1). Adds one extra seed slot
                                           (3 -> 4 for Single, 7 -> 8 for Triple). Must be
                                           called BEFORE the first encrypt — switching
                                           mid-session returns ITB_EASY_LOCKSEED_AFTER_ENCRYPT. */

/* Persistence blob — carries seeds + PRF keys + MAC key (and the
 * dedicated lockSeed material when set_lock_seed(1) is active). */
uint8_t *blob = NULL;
size_t   blob_len = 0;
itb_encryptor_export(enc, &blob, &blob_len);
printf("state blob: %zu bytes\n", blob_len);

const char *plaintext = "any text or binary data - including 0x00 bytes";
size_t plaintext_len = strlen(plaintext);

/* Authenticated encrypt — 32-byte tag is computed across the
 * entire decrypted capacity and embedded inside the RGBWYOPA
 * container, preserving oracle-free deniability. */
uint8_t *encrypted = NULL;
size_t   encrypted_len = 0;
itb_encryptor_encrypt_auth(enc, plaintext, plaintext_len,
                           &encrypted, &encrypted_len);
printf("encrypted: %zu bytes\n", encrypted_len);

/* Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived. */
uint8_t *outerKey = NULL;
size_t   outerKey_len = 0;
itb_wrapper_generate_key(ITB_WRAPPER_CIPHER_AES_128_CTR,
                         &outerKey, &outerKey_len);
// itb_wrapper_derive_key(ITB_WRAPPER_CIPHER_AES_128_CTR, master, master_len,
//                        &outerKey, &outerKey_len);

/* Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case). */
uint8_t nonce_buf[16] = {0};
itb_wrap_in_place(ITB_WRAPPER_CIPHER_AES_128_CTR,
                  outerKey, outerKey_len,
                  encrypted, encrypted_len,
                  nonce_buf, sizeof nonce_buf);
size_t nlen = 0;
itb_wrapper_nonce_size(ITB_WRAPPER_CIPHER_AES_128_CTR, &nlen);

/* Compose the on-wire blob: `nonce || mutated-ciphertext`. */
size_t   wire_len = nlen + encrypted_len;
uint8_t *wire     = (uint8_t *) malloc(wire_len);
memcpy(wire, nonce_buf, nlen);
memcpy(wire + nlen, encrypted, encrypted_len);

/* Streaming alternative — slice plaintext into chunk_size pieces
 * and call itb_encryptor_encrypt_auth() per chunk; each chunk
 * carries its own MAC tag. itb_encryptor_header_size() and
 * itb_encryptor_parse_chunk_len() are per-instance accessors
 * (track this encryptor's own nonce_bits, NOT the process-wide
 * itb_header_size). */

/* Send `wire` + `blob` + `outerKey` (out-of-band); itb_encryptor_close
 * zeroes key material on the Go side and itb_encryptor_free
 * deallocates the wrapper. */
free(wire);
itb_buffer_free(encrypted);
itb_buffer_free(outerKey);
itb_buffer_free(blob);
itb_encryptor_close(enc);
itb_encryptor_free(enc);


/* Receiver */

/* Receive on-wire blob + state blob + outerKey (out-of-band). */
/* uint8_t *wire = ...; size_t wire_len = ...; */
/* uint8_t *blob = ...; size_t blob_len = ...; */
/* uint8_t *outerKey = ...; size_t outerKey_len = ...; */

/* Strip nonce + XOR-decrypt the body in place; `wire[nlen..wire_len)`
 * holds the ITB ciphertext after the call. */
size_t nlen_r = 0;
itb_wrapper_nonce_size(ITB_WRAPPER_CIPHER_AES_128_CTR, &nlen_r);
itb_unwrap_in_place(ITB_WRAPPER_CIPHER_AES_128_CTR,
                    outerKey, outerKey_len, wire, wire_len);
const uint8_t *encrypted     = wire + nlen_r;
size_t         encrypted_len = wire_len - nlen_r;

itb_set_max_workers(8);  /* limit to 8 CPU cores (default: 0 = all CPUs) */

/* Optional: peek at the blob's metadata before constructing a
 * matching encryptor. Useful when the receiver multiplexes blobs
 * of different shapes (different primitive / mode / MAC choices). */
char prim_buf[64], mac_buf[64];
size_t prim_len = 0, mac_len = 0;
int peek_kb = 0, peek_mode = 0;
itb_easy_peek_config(blob, blob_len,
                     prim_buf, sizeof prim_buf, &prim_len,
                     &peek_kb, &peek_mode,
                     mac_buf, sizeof mac_buf, &mac_len);
printf("peek: primitive=%s, key_bits=%d, mode=%d, mac=%s\n",
       prim_buf, peek_kb, peek_mode, mac_buf);

itb_encryptor_t *dec = NULL;
itb_encryptor_new(prim_buf, peek_kb, mac_buf, peek_mode, &dec);

/* itb_encryptor_import(dec, blob, blob_len) below automatically
 * restores the full per-instance configuration (nonce_bits,
 * barrier_fill, bit_soup, lock_soup, lock_batch, and the dedicated lockSeed
 * material when sender's set_lock_seed(1) was active). The set_*
 * lines below are kept for documentation — they show the knobs
 * available for explicit pre-Import override. barrier_fill is
 * asymmetric: a receiver-set value > 1 takes priority over the
 * blob's barrier_fill (the receiver's heavier CSPRNG margin is
 * preserved across Import). */
itb_encryptor_set_nonce_bits(dec, 512);
itb_encryptor_set_barrier_fill(dec, 4);
itb_encryptor_set_bit_soup(dec, 1);
itb_encryptor_set_lock_soup(dec, 1);
itb_encryptor_set_lock_batch(dec, 1);      /* Recommended under the PRF assumption — the performance Lock Soup mode; symmetric, set on both sides. */
/* itb_encryptor_set_lock_seed(dec, 1);   optional — Import below restores
                                          the dedicated lockSeed slot from
                                          the blob's lock_seed:true. */

/* Restore PRF keys, seed components, MAC key, and the per-instance
 * configuration overrides (nonce_bits / barrier_fill / bit_soup /
 * lock_soup / lock_batch / lock_seed) from the saved blob. */
itb_encryptor_import(dec, blob, blob_len);

/* Authenticated decrypt — any single-bit tamper triggers MAC
 * failure (no oracle leak about which byte was tampered). Mismatch
 * surfaces as ITB_MAC_FAILURE, not a corrupted plaintext. */
uint8_t *plaintext_out = NULL;
size_t   plaintext_out_len = 0;
itb_status_t st = itb_encryptor_decrypt_auth(dec, encrypted, encrypted_len,
                                             &plaintext_out, &plaintext_out_len);
if (st == ITB_OK) {
    printf("decrypted: %.*s\n", (int) plaintext_out_len, (const char *) plaintext_out);
    itb_buffer_free(plaintext_out);
} else if (st == ITB_MAC_FAILURE) {
    printf("MAC verification failed -- tampered or wrong key\n");
} else {
    printf("decrypt error: code=%d msg=%s\n", st, itb_last_error());
}

itb_encryptor_close(dec);
itb_encryptor_free(dec);
```

### Output-buffer ownership contract

Each cipher method
(`itb_encryptor_encrypt` / `itb_encryptor_decrypt` /
`itb_encryptor_encrypt_auth` / `itb_encryptor_decrypt_auth`) returns a
**freshly malloc'd user-owned buffer** via `*out_buf` with the visible
length in `*out_len`. The caller releases the buffer with
`itb_buffer_free()`. The encryptor's internal cache (the libitb FFI
write target) is invisible to the caller and lives across calls; what
reaches the caller is always a fresh copy. The cached bytes are zeroed
on grow / `itb_encryptor_close` / `itb_encryptor_free`, so residual
ciphertext / plaintext does not linger in heap memory beyond the next
cipher call.

## Quick Start — Mixed primitives (Different PRF per seed slot)

`itb_encryptor_new_mixed` and `itb_encryptor_new_mixed3` accept
per-slot primitive names — the noise / data / start (and optional
dedicated lockSeed) seed slots can use different PRF primitives within
the same native hash width. The mix-and-match-PRF freedom of the
lower-level path, surfaced through the high-level encryptor without
forcing the caller off the Easy Mode constructor. The state blob
carries per-slot primitives + per-slot PRF keys; the receiver
constructs a matching encryptor with the same arguments and calls
`itb_encryptor_import` to restore.

```c
/* Sender */

#include <itb.h>
#include <stdio.h>
#include <string.h>

/* Per-slot primitive selection (Single Ouroboros, 3 + 1 slots).
 * Every name must share the same native hash width — mixing widths
 * surfaces ITB_SEED_WIDTH_MIX at construction time.
 * Triple Ouroboros mirror — itb_encryptor_new_mixed3 takes seven
 * per-slot names (noise + 3 data + 3 start) plus the optional
 * prim_l lockSeed. */
itb_encryptor_t *enc = NULL;
itb_encryptor_new_mixed(
    "blake3",         /* prim_n: noiseSeed:  BLAKE3 */
    "blake2s",        /* prim_d: dataSeed:   BLAKE2s */
    "areion256",      /* prim_s: startSeed:  Areion-SoEM-256 */
    "blake2b256",     /* prim_l: dedicated lockSeed (NULL or "" for no lockSeed slot) */
    1024,             /* key_bits */
    "hmac-blake3",    /* mac_name */
    &enc);

/* Per-instance configuration applies as for itb_encryptor_new. */
itb_encryptor_set_nonce_bits(enc, 512);
itb_encryptor_set_barrier_fill(enc, 4);
/* BitSoup + LockSoup are auto-coupled on the on-direction by
 * prim_l above; explicit calls below are unnecessary but harmless
 * if added. */
/* itb_encryptor_set_bit_soup(enc, 1); */
/* itb_encryptor_set_lock_soup(enc, 1); */

/* Per-slot introspection — itb_encryptor_primitive returns "mixed"
 * literal, itb_encryptor_primitive_at(slot) returns each slot's
 * name, itb_encryptor_is_mixed is the typed predicate. Slot
 * ordering is canonical: 0 = noiseSeed, 1 = dataSeed, 2 = startSeed,
 * 3 = lockSeed (Single); Triple grows the middle range to 7 slots
 * + lockSeed. */
int is_mixed = 0;
itb_encryptor_is_mixed(enc, &is_mixed);
char namebuf[64];
size_t name_len = 0;
itb_encryptor_primitive(enc, namebuf, sizeof namebuf, &name_len);
printf("mixed=%d primitive=%s\n", is_mixed, namebuf);
for (int i = 0; i < 4; i++) {
    itb_encryptor_primitive_at(enc, i, namebuf, sizeof namebuf, &name_len);
    printf("  slot %d: %s\n", i, namebuf);
}

uint8_t *blob = NULL;
size_t   blob_len = 0;
itb_encryptor_export(enc, &blob, &blob_len);
printf("state blob: %zu bytes\n", blob_len);

const char *plaintext = "mixed-primitive Easy Mode payload";
uint8_t *encrypted = NULL;
size_t   encrypted_len = 0;
itb_encryptor_encrypt_auth(enc, plaintext, strlen(plaintext),
                           &encrypted, &encrypted_len);

/* Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived. */
uint8_t *outerKey = NULL;
size_t   outerKey_len = 0;
itb_wrapper_generate_key(ITB_WRAPPER_CIPHER_AES_128_CTR,
                         &outerKey, &outerKey_len);
// itb_wrapper_derive_key(ITB_WRAPPER_CIPHER_AES_128_CTR, master, master_len,
//                        &outerKey, &outerKey_len);

/* Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case). */
uint8_t nonce_buf[16] = {0};
itb_wrap_in_place(ITB_WRAPPER_CIPHER_AES_128_CTR,
                  outerKey, outerKey_len,
                  encrypted, encrypted_len,
                  nonce_buf, sizeof nonce_buf);
size_t nlen = 0;
itb_wrapper_nonce_size(ITB_WRAPPER_CIPHER_AES_128_CTR, &nlen);

size_t   wire_len = nlen + encrypted_len;
uint8_t *wire     = (uint8_t *) malloc(wire_len);
memcpy(wire, nonce_buf, nlen);
memcpy(wire + nlen, encrypted, encrypted_len);


/* Receiver */

/* Receive on-wire blob + state blob + outerKey (out-of-band). */
/* uint8_t *wire = ...; size_t wire_len = ...; */
/* uint8_t *blob = ...; size_t blob_len = ...; */
/* uint8_t *outerKey = ...; size_t outerKey_len = ...; */

size_t nlen_r = 0;
itb_wrapper_nonce_size(ITB_WRAPPER_CIPHER_AES_128_CTR, &nlen_r);
itb_unwrap_in_place(ITB_WRAPPER_CIPHER_AES_128_CTR,
                    outerKey, outerKey_len, wire, wire_len);
const uint8_t *encrypted_r     = wire + nlen_r;
size_t         encrypted_r_len = wire_len - nlen_r;

/* Receiver constructs a matching mixed encryptor — every per-slot
 * primitive name plus key_bits and mac_name must agree with the
 * sender. itb_encryptor_import validates each per-slot primitive
 * against the receiver's bound spec; mismatches surface as
 * ITB_EASY_MISMATCH with the offending JSON field name retrievable
 * via itb_easy_last_mismatch_field. */
itb_encryptor_t *dec = NULL;
itb_encryptor_new_mixed(
    "blake3", "blake2s", "areion256", "blake2b256",
    1024, "hmac-blake3", &dec);

itb_encryptor_import(dec, blob, blob_len);

uint8_t *decrypted = NULL;
size_t   decrypted_len = 0;
itb_encryptor_decrypt_auth(dec, encrypted_r, encrypted_r_len,
                           &decrypted, &decrypted_len);
printf("decrypted: %.*s\n", (int) decrypted_len, (const char *) decrypted);

free(wire);
itb_buffer_free(outerKey);
```

## Quick Start — Triple Ouroboros

Triple Ouroboros (3× security: P × 2^(3×key_bits)) takes seven seeds
(one shared `noiseSeed` plus three `dataSeed` and three `startSeed`)
on the low-level path, all wrapped behind a single `itb_encryptor_new`
call when `mode = 3` is passed to the constructor.

```c
#include <itb.h>
#include <stdlib.h>
#include <string.h>

/* mode=3 selects Triple Ouroboros. All other constructor arguments
 * behave identically to the Single (mode=1) case shown above. */
itb_encryptor_t *enc = NULL;
itb_encryptor_new("areion512", 2048, "hmac-blake3", 3, &enc);

const char *plaintext = "Triple Ouroboros payload";

uint8_t *encrypted = NULL;
size_t   encrypted_len = 0;
itb_encryptor_encrypt_auth(enc, plaintext, strlen(plaintext),
                           &encrypted, &encrypted_len);

/* Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived. */
uint8_t *outerKey = NULL;
size_t   outerKey_len = 0;
itb_wrapper_generate_key(ITB_WRAPPER_CIPHER_AES_128_CTR,
                         &outerKey, &outerKey_len);
// itb_wrapper_derive_key(ITB_WRAPPER_CIPHER_AES_128_CTR, master, master_len,
//                        &outerKey, &outerKey_len);

/* Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case). */
uint8_t nonce_buf[16] = {0};
itb_wrap_in_place(ITB_WRAPPER_CIPHER_AES_128_CTR,
                  outerKey, outerKey_len,
                  encrypted, encrypted_len,
                  nonce_buf, sizeof nonce_buf);
size_t nlen = 0;
itb_wrapper_nonce_size(ITB_WRAPPER_CIPHER_AES_128_CTR, &nlen);

size_t   wire_len = nlen + encrypted_len;
uint8_t *wire     = (uint8_t *) malloc(wire_len);
memcpy(wire, nonce_buf, nlen);
memcpy(wire + nlen, encrypted, encrypted_len);

/* Receiver: strip nonce + XOR-decrypt body in place. */
itb_unwrap_in_place(ITB_WRAPPER_CIPHER_AES_128_CTR,
                    outerKey, outerKey_len, wire, wire_len);

uint8_t *decrypted = NULL;
size_t   decrypted_len = 0;
itb_encryptor_decrypt_auth(enc, wire + nlen, wire_len - nlen,
                           &decrypted, &decrypted_len);

free(wire);
itb_buffer_free(outerKey);
itb_buffer_free(encrypted);
itb_buffer_free(decrypted);
itb_encryptor_close(enc);
itb_encryptor_free(enc);
```

The seven-seed split is internal to the encryptor; the on-wire
ciphertext format is identical in shape to Single Ouroboros — only the
internal payload split / interleave differs. Mixed-primitive Triple is
reachable via `itb_encryptor_new_mixed3`.

## Quick Start — Areion-SoEM-512 + HMAC-BLAKE3 (Low-Level, MAC Authenticated)

The lower-level path uses explicit `itb_seed_t` handles for the
noise / data / start trio plus an optional dedicated lock seed wired in
through `itb_seed_attach_lock_seed`. Useful when the caller needs full
control over per-slot keying (e.g. PRF material stored in an HSM) or
when slotting into the existing Go `itb.Encrypt` / `itb.Decrypt` call
surface from a C client. The high-level `itb_encryptor_t` above wraps
this same path with one constructor call.

```c
/* Sender */

#include <itb.h>
#include <stdio.h>
#include <string.h>

/* Optional: global configuration (all process-wide, atomic) */
itb_set_max_workers(8);     /* limit to 8 CPU cores (default: 0 = all CPUs) */
itb_set_nonce_bits(512);    /* 512-bit nonce (default: 128-bit) */
itb_set_barrier_fill(4);    /* CSPRNG fill margin (default: 1, valid: 1, 2, 4, 8, 16, 32) */

itb_set_bit_soup(1);        /* optional bit-level split ("bit-soup"; default: 0 = byte-level) */
                            /* automatically enabled for Single Ouroboros if
                             * itb_set_lock_soup(1) is enabled or vice versa */

itb_set_lock_soup(1);       /* optional Insane Interlocked Mode: per-chunk PRF-keyed
                             * bit-permutation overlay on top of bit-soup;
                             * automatically enabled for Single Ouroboros if
                             * itb_set_bit_soup(1) is enabled or vice versa */
itb_set_lock_batch(1);      /* Lock Batch is the performance Lock Soup mode: recommended
                             * in every case when the configured hash is PRF-grade, since
                             * security is preserved under the PRF assumption while
                             * throughput rises. Symmetric option — set identically on
                             * the encrypt and decrypt sides. */

/* Three independent CSPRNG-keyed Areion-SoEM-512 seeds. Each Seed
 * pre-keys its primitive once at construction; the C ABI / FFI
 * layer auto-wires the AVX-512 + VAES + ILP + ZMM-batched chain-
 * absorb dispatch through the Seed's BatchHash arm — no manual
 * batched-arm attachment is required on the C side. */
itb_seed_t *ns = NULL, *ds = NULL, *ss = NULL;
itb_seed_new("areion512", 2048, &ns);   /* random noise CSPRNG seeds + hash key generated */
itb_seed_new("areion512", 2048, &ds);   /* random data  CSPRNG seeds + hash key generated */
itb_seed_new("areion512", 2048, &ss);   /* random start CSPRNG seeds + hash key generated */

/* Optional: dedicated lockSeed for the bit-permutation derivation
 * channel. Separates that PRF's keying material from the noiseSeed-
 * driven noise-injection channel without changing the public
 * encrypt / decrypt signatures. The bit-permutation overlay must
 * be engaged (itb_set_bit_soup(1) or itb_set_lock_soup(1) — both
 * already on above) before the first encrypt; the build-PRF guard
 * fires on encrypt-time when an attach is present without either
 * flag. */
itb_seed_t *ls = NULL;
itb_seed_new("areion512", 2048, &ls);   /* random lock CSPRNG seeds + hash key generated */
itb_seed_attach_lock_seed(ns, ls);

/* HMAC-BLAKE3 — 32-byte CSPRNG key, 32-byte tag. Real code should
 * pull the key bytes from a CSPRNG (e.g. /dev/urandom via fread);
 * the zero key here is for example purposes only. */
uint8_t mac_key[32] = {0};
itb_mac_t *mac = NULL;
itb_mac_new("hmac-blake3", mac_key, sizeof mac_key, &mac);

const char *plaintext = "any text or binary data - including 0x00 bytes";

/* Authenticated encrypt — 32-byte tag is computed across the
 * entire decrypted capacity and embedded inside the RGBWYOPA
 * container, preserving oracle-free deniability. */
uint8_t *encrypted = NULL;
size_t   encrypted_len = 0;
itb_encrypt_auth(ns, ds, ss, mac, plaintext, strlen(plaintext),
                 &encrypted, &encrypted_len);
printf("encrypted: %zu bytes\n", encrypted_len);

/* Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived. */
uint8_t *outerKey = NULL;
size_t   outerKey_len = 0;
itb_wrapper_generate_key(ITB_WRAPPER_CIPHER_AES_128_CTR,
                         &outerKey, &outerKey_len);
// itb_wrapper_derive_key(ITB_WRAPPER_CIPHER_AES_128_CTR, master, master_len,
//                        &outerKey, &outerKey_len);

/* Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case). */
uint8_t nonce_buf[16] = {0};
itb_wrap_in_place(ITB_WRAPPER_CIPHER_AES_128_CTR,
                  outerKey, outerKey_len,
                  encrypted, encrypted_len,
                  nonce_buf, sizeof nonce_buf);
size_t nlen = 0;
itb_wrapper_nonce_size(ITB_WRAPPER_CIPHER_AES_128_CTR, &nlen);

size_t   wire_len = nlen + encrypted_len;
uint8_t *wire     = (uint8_t *) malloc(wire_len);
memcpy(wire, nonce_buf, nlen);
memcpy(wire + nlen, encrypted, encrypted_len);

/* Cross-process persistence: Blob512 packs every seed's hash key
 * + components, the optional dedicated lockSeed, and the MAC key
 * + name into one JSON blob alongside the captured process-wide
 * globals. ITB_BLOB_OPT_LOCKSEED / ITB_BLOB_OPT_MAC opt the
 * corresponding sections in. */
itb_blob512_t *blob = NULL;
itb_blob512_new(&blob);

uint8_t hk_buf[64];
size_t  hk_len = 0;
uint64_t comp_buf[32];
size_t   comp_count = 0;

itb_seed_hash_key(ns, hk_buf, sizeof hk_buf, &hk_len);
itb_blob512_set_key(blob, ITB_BLOB_SLOT_N, hk_buf, hk_len);
itb_seed_components(ns, comp_buf, 32, &comp_count);
itb_blob512_set_components(blob, ITB_BLOB_SLOT_N, comp_buf, comp_count);

itb_seed_hash_key(ds, hk_buf, sizeof hk_buf, &hk_len);
itb_blob512_set_key(blob, ITB_BLOB_SLOT_D, hk_buf, hk_len);
itb_seed_components(ds, comp_buf, 32, &comp_count);
itb_blob512_set_components(blob, ITB_BLOB_SLOT_D, comp_buf, comp_count);

itb_seed_hash_key(ss, hk_buf, sizeof hk_buf, &hk_len);
itb_blob512_set_key(blob, ITB_BLOB_SLOT_S, hk_buf, hk_len);
itb_seed_components(ss, comp_buf, 32, &comp_count);
itb_blob512_set_components(blob, ITB_BLOB_SLOT_S, comp_buf, comp_count);

itb_seed_hash_key(ls, hk_buf, sizeof hk_buf, &hk_len);
itb_blob512_set_key(blob, ITB_BLOB_SLOT_L, hk_buf, hk_len);
itb_seed_components(ls, comp_buf, 32, &comp_count);
itb_blob512_set_components(blob, ITB_BLOB_SLOT_L, comp_buf, comp_count);

itb_blob512_set_mac_key(blob, mac_key, sizeof mac_key);
itb_blob512_set_mac_name(blob, "hmac-blake3");

uint8_t *blob_bytes = NULL;
size_t   blob_bytes_len = 0;
itb_blob512_export(blob, ITB_BLOB_OPT_LOCKSEED | ITB_BLOB_OPT_MAC,
                   &blob_bytes, &blob_bytes_len);
printf("persistence blob: %zu bytes\n", blob_bytes_len);

/* Send `wire` + `blob_bytes` + `outerKey` (out-of-band). Release
 * everything below. */
free(wire);
itb_buffer_free(outerKey);
itb_buffer_free(encrypted);
itb_buffer_free(blob_bytes);
itb_blob512_free(blob);
itb_mac_free(mac);
itb_seed_free(ls);
itb_seed_free(ss);
itb_seed_free(ds);
itb_seed_free(ns);


/* Receiver */

itb_set_max_workers(8);   /* deployment knob — not serialised by Blob512 */

/* Receive on-wire blob + blob_bytes + outerKey (out-of-band). */
/* uint8_t *wire = ...; size_t wire_len = ...; */
/* uint8_t *blob_bytes = ...; size_t blob_bytes_len = ...; */
/* uint8_t *outerKey = ...; size_t outerKey_len = ...; */

/* Strip nonce + XOR-decrypt the body in place; wire[nlen..wire_len)
 * holds the ITB ciphertext after the call. */
size_t nlen_r = 0;
itb_wrapper_nonce_size(ITB_WRAPPER_CIPHER_AES_128_CTR, &nlen_r);
itb_unwrap_in_place(ITB_WRAPPER_CIPHER_AES_128_CTR,
                    outerKey, outerKey_len, wire, wire_len);
const uint8_t *encrypted_r     = wire + nlen_r;
size_t         encrypted_r_len = wire_len - nlen_r;
(void) encrypted_r; (void) encrypted_r_len;

/* itb_blob512_import restores per-slot hash keys + components AND
 * applies the captured globals (nonce_bits / barrier_fill / bit_soup
 * / lock_soup) via the process-wide setters. */
itb_blob512_t *restored = NULL;
itb_blob512_new(&restored);
itb_blob512_import(restored, blob_bytes, blob_bytes_len);

uint8_t  hk2[64];
size_t   hk2_len = 0;
uint64_t comp2[32];
size_t   comp2_count = 0;

itb_blob512_get_key(restored, ITB_BLOB_SLOT_N, hk2, sizeof hk2, &hk2_len);
itb_blob512_get_components(restored, ITB_BLOB_SLOT_N, comp2, 32, &comp2_count);
itb_seed_t *ns2 = NULL;
itb_seed_from_components("areion512", comp2, comp2_count,
                         hk2, hk2_len, &ns2);
/* ... wire ds2, ss2, ls2 the same way; rebuild MAC; itb_decrypt_auth ... */
```

## Streams — chunked I/O over caller-owned read / write callbacks

`itb_stream_encrypt` / `itb_stream_decrypt` (and the seven-seed
counterparts `itb_stream_encrypt_triple` / `itb_stream_decrypt_triple`)
wrap the Single Message Encrypt / Decrypt API behind a chunked I/O surface.
ITB ciphertexts cap at ~64 MB plaintext per chunk; streaming larger
payloads slices the input into chunks at the binding layer, encrypts
each chunk through the regular FFI path, and concatenates the results.
Memory peak is bounded by `chunk_size` regardless of the total
payload length. The caller MUST pass `chunk_size > 0` — zero is
rejected with `ITB_BAD_INPUT`. `ITB_DEFAULT_CHUNK_SIZE` (16 MiB)
is exposed as a recommended starting value for callers without a
domain-specific preference.

The stream wrappers take Seeds (and an optional MAC), NOT an
`itb_encryptor_t` handle — matching the canonical cross-binding
contract. The caller supplies a
`(read_fn, user_ctx)` pair for the input source and a
`(write_fn, user_ctx)` pair for the output sink, where the `user_ctx`
pointers carry caller state (file descriptor, in-memory buffer cursor,
etc.) without globals. `read_fn` signals EOF via `*out_n = 0`; `write_fn`
must consume the full `(buf, n)` span before returning. Either callback
returning a non-zero status code aborts the stream operation with
`ITB_INTERNAL`.

```c
#include <itb.h>
#include <string.h>

/* Caller state shared between read and write callbacks. */
struct buf_ctx {
    const uint8_t *src;
    size_t         src_len;
    size_t         src_pos;
    uint8_t       *sink;
    size_t         sink_len;
    size_t         sink_cap;
};

static int read_cb(void *user_ctx, void *buf, size_t cap, size_t *out_n)
{
    struct buf_ctx *c = user_ctx;
    size_t take = c->src_len - c->src_pos;
    if (take > cap) take = cap;
    memcpy(buf, c->src + c->src_pos, take);
    c->src_pos += take;
    *out_n = take;
    return 0;
}

static int write_cb(void *user_ctx, const void *buf, size_t n)
{
    struct buf_ctx *c = user_ctx;
    if (c->sink_len + n > c->sink_cap) {
        size_t new_cap = c->sink_cap ? c->sink_cap * 2 : 4096;
        while (new_cap < c->sink_len + n) new_cap *= 2;
        uint8_t *p = realloc(c->sink, new_cap);
        if (!p) return 1;
        c->sink = p;
        c->sink_cap = new_cap;
    }
    memcpy(c->sink + c->sink_len, buf, n);
    c->sink_len += n;
    return 0;
}

/* Encrypt direction: read plaintext from `src`, collect ITB stream
 * into `ectx.sink`, then wrap the whole transcript end-to-end through
 * one keystream session. */
itb_seed_t *n = NULL, *d = NULL, *s = NULL;
itb_seed_new("blake3", 1024, &n);
itb_seed_new("blake3", 1024, &d);
itb_seed_new("blake3", 1024, &s);

const char *src = "the streamed payload, possibly many MiB long";
struct buf_ctx ectx = {
    .src = (const uint8_t *) src, .src_len = strlen(src), .src_pos = 0,
    .sink = NULL, .sink_len = 0, .sink_cap = 0,
};
itb_stream_encrypt(n, d, s, /* mac */ NULL,
                   read_cb, &ectx,
                   write_cb, &ectx,
                   ITB_DEFAULT_CHUNK_SIZE);   /* chunk_size — must be > 0 */

/* Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived. */
uint8_t *outerKey = NULL; size_t outerKey_len = 0;
itb_wrapper_generate_key(ITB_WRAPPER_CIPHER_AES_128_CTR,
                         &outerKey, &outerKey_len);
// itb_wrapper_derive_key(ITB_WRAPPER_CIPHER_AES_128_CTR, master, master_len,
//                        &outerKey, &outerKey_len);

/* Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case). */
uint8_t nonce_buf[16] = {0};
itb_wrap_stream_writer_t *ww = NULL;
itb_wrap_stream_writer_new(ITB_WRAPPER_CIPHER_AES_128_CTR,
                           outerKey, outerKey_len,
                           nonce_buf, sizeof nonce_buf, &ww);
size_t nlen = 0;
itb_wrapper_nonce_size(ITB_WRAPPER_CIPHER_AES_128_CTR, &nlen);

/* Wrap the inner stream end-to-end through one keystream session. */
itb_wrap_stream_writer_update(ww, ectx.sink, ectx.sink_len,
                              ectx.sink, ectx.sink_cap);
itb_wrap_stream_writer_free(ww);

/* Receiver: strip nonce, unwrap body, feed to itb_stream_decrypt. */
itb_unwrap_stream_reader_t *ur = NULL;
itb_unwrap_stream_reader_new(ITB_WRAPPER_CIPHER_AES_128_CTR,
                             outerKey, outerKey_len,
                             nonce_buf, nlen, &ur);
itb_unwrap_stream_reader_update(ur, ectx.sink, ectx.sink_len,
                                ectx.sink, ectx.sink_cap);
itb_unwrap_stream_reader_free(ur);

/* Decrypt direction: feed `ectx.sink` back through, recover plaintext. */
struct buf_ctx dctx = {
    .src = ectx.sink, .src_len = ectx.sink_len, .src_pos = 0,
    .sink = NULL, .sink_len = 0, .sink_cap = 0,
};
itb_stream_decrypt(n, d, s, NULL,
                   read_cb, &dctx,
                   write_cb, &dctx,
                   0);

/* dctx.sink now holds the recovered plaintext. */
itb_buffer_free(outerKey);
free(ectx.sink);
free(dctx.sink);
itb_seed_free(s);
itb_seed_free(d);
itb_seed_free(n);
```

Switching `itb_set_nonce_bits` mid-stream produces a chunk header
layout the paired decryptor (which snapshots `itb_header_size` at
chunk boundary) cannot parse — the nonce size must be stable for the
lifetime of one stream pair.

### Seed-lifetime contract on streams

The stream entry points cache the raw libitb handles internally. Every
Seed (and the optional MAC) handed to a stream call MUST remain alive —
un-freed — for the entire call. Letting any seed go out of scope before
the call returns is undefined behaviour (use-after-free in the FFI
call). C relies on caller discipline. Practical pattern: declare the
Seeds in the same scope as the stream call, free them only after the
call returns.

## Native Blob — low-level state persistence

`itb_blob128_t` / `itb_blob256_t` / `itb_blob512_t` wrap the libitb
Native Blob C ABI: width-specific containers that pack the low-level
encryptor material (per-seed hash key + components + optional dedicated
lockSeed + optional MAC key + name) plus the captured process-wide
configuration into one self-describing JSON blob. Used on the
lower-level encrypt / decrypt path where each seed slot may carry a
different primitive — the high-level `itb_encryptor_export` wraps a
narrower one-primitive-per-encryptor surface that uses the same wire
format under the hood.

Slot constants (defined in `<itb.h>`):

| Constant | Value | Meaning |
|---|---|---|
| `ITB_BLOB_SLOT_N` | 0 | shared: noiseSeed + KeyN |
| `ITB_BLOB_SLOT_D` | 1 | Single: dataSeed + KeyD |
| `ITB_BLOB_SLOT_S` | 2 | Single: startSeed + KeyS |
| `ITB_BLOB_SLOT_L` | 3 | optional any mode: dedicated lockSeed |
| `ITB_BLOB_SLOT_D1` | 4 | Triple: dataSeed1 + KeyD1 |
| `ITB_BLOB_SLOT_D2` | 5 | Triple: dataSeed2 + KeyD2 |
| `ITB_BLOB_SLOT_D3` | 6 | Triple: dataSeed3 + KeyD3 |
| `ITB_BLOB_SLOT_S1` | 7 | Triple: startSeed1 + KeyS1 |
| `ITB_BLOB_SLOT_S2` | 8 | Triple: startSeed2 + KeyS2 |
| `ITB_BLOB_SLOT_S3` | 9 | Triple: startSeed3 + KeyS3 |

Export option bitmask (`opts` parameter on `itb_blobW_export` /
`itb_blobW_export3`):

| Constant | Value | Meaning |
|---|---|---|
| `ITB_BLOB_OPT_LOCKSEED` | `1 << 0` | emit `l` slot (KeyL + components) |
| `ITB_BLOB_OPT_MAC` | `1 << 1` | emit MAC key + name |

The blob is mode-discriminated: `itb_blobW_export` packs Single
material, `itb_blobW_export3` packs Triple material; the matching
`itb_blobW_import` / `itb_blobW_import3` receivers reject the wrong
importer with `ITB_BLOB_MODE_MISMATCH`. Globals (NonceBits / BarrierFill
/ BitSoup / LockSoup) are captured into the blob at export time and
applied process-wide on import via the corresponding `itb_set_*`
setters.

## Hash primitives (Single / Triple)

Names match the canonical `hashes/` registry. Triple Ouroboros takes
seven seeds (one shared `noiseSeed` plus three `dataSeed` and three
`startSeed`) via `itb_encrypt_triple` / `itb_decrypt_triple` and the
authenticated counterparts `itb_encrypt_auth_triple` /
`itb_decrypt_auth_triple`. Streaming counterparts:
`itb_stream_encrypt_triple` / `itb_stream_decrypt_triple`.

All seeds passed to one encrypt / decrypt call must share the same
native hash width. Mixing widths surfaces `ITB_SEED_WIDTH_MIX`.

## MAC primitives

Names match the libitb MAC registry; ordering matches that registry's declaration order.

| MAC | Key bytes | Tag bytes | Underlying primitive |
|---|---|---|---|
| `kmac256` | 32 | 32 | KMAC256 (Keccak-derived) |
| `hmac-sha256` | 32 | 32 | HMAC over SHA-256 |
| `hmac-blake3` | 32 | 32 | HMAC over BLAKE3 |

`kmac256` and `hmac-sha256` accept keys 16 bytes and longer; the binding fleet's tests and examples use 32 bytes uniformly across primitives for cross-binding consistency. `hmac-blake3` requires exactly 32 bytes by construction.

## Process-wide configuration

Every setter takes effect for all subsequent encrypt / decrypt calls in
the process. Out-of-range values surface as `ITB_BAD_INPUT` rather
than crashing.

| Function | Accepted values | Default |
|---|---|---|
| `itb_set_max_workers(n)` | non-negative int | 0 (auto) |
| `itb_set_nonce_bits(n)` | 128, 256, 512 | 128 |
| `itb_set_barrier_fill(n)` | 1, 2, 4, 8, 16, 32 | 1 |
| `itb_set_bit_soup(mode)` | 0 (off), non-zero (on) | 0 |
| `itb_set_lock_soup(mode)` | 0 (off), non-zero (on) | 0 |
| `itb_set_lock_batch(mode)` | 0 (off), non-zero (on) | 0 |

Read-only constants: `itb_max_key_bits()`, `itb_channels()`,
`itb_header_size()`, `itb_version(out, cap, &out_len)`.

For low-level chunk parsing (e.g. when implementing custom file formats
around ITB chunks): `itb_parse_chunk_len(header, header_len, &out)`
inspects the fixed-size chunk header and returns the chunk's total
on-the-wire length; `itb_header_size()` returns the active header byte
count (20 / 36 / 68 for nonce sizes 128 / 256 / 512 bits).

MAC names available via `itb_mac_count` + `itb_mac_name`: `kmac256`,
`hmac-sha256`, `hmac-blake3`. Hash names via `itb_hash_count` +
`itb_hash_name`.

## Concurrency

A single `itb_encryptor_t` is **not safe** for concurrent use from
multiple threads — cipher methods (`itb_encryptor_encrypt` /
`itb_encryptor_decrypt` / `itb_encryptor_encrypt_auth` /
`itb_encryptor_decrypt_auth`), per-instance setters, and
`itb_encryptor_close` / `itb_encryptor_import` all mutate per-instance
state without locking. Sharing one encryptor across threads requires
external synchronisation; distinct encryptor handles, each owned by
one thread, run independently against the libitb worker pool.

By contrast, the low-level cipher free functions (`itb_encrypt` /
`itb_decrypt` / `itb_encrypt_auth` / `itb_decrypt_auth` plus the
Triple-Ouroboros counterparts) take read-only Seed pointers and
allocate output per call — they are thread-safe under concurrent
invocation on the same seeds. The exception is the per-instance Config
snapshot inside `itb_encryptor_t`: concurrent setter mutations on a
Config that other threads are reading must be serialised by the
caller. Process-wide `itb_set_*` setters (`itb_set_nonce_bits` /
`itb_set_barrier_fill` / `itb_set_max_workers` / `itb_set_bit_soup` /
`itb_set_lock_soup`) are atomic and safe to call from any thread; the
caveat is logical, not atomic — changing a knob WHILE an encrypt /
decrypt call is in flight can corrupt that operation, since the cipher
snapshots the configuration at call entry and a mid-flight change
breaks the running invariants.

`itb_seed_attach_lock_seed` mutates seed state (not a single atomic
counter) and is **not thread-safe** — call it outside any in-flight
cipher operation on the same noise seed.

The textual diagnostic surfaced by `itb_last_error()` is captured into
thread-local storage on every failing call, so concurrent threads do
not race on it. The structural status code returned by every entry
point is unaffected by thread interleaving.

**Signal-handler reentrance.** None of the binding's public entry
points are async-signal-safe. They allocate via libc `malloc`, mutate
the per-thread last-error TLS buffer, and dispatch to libitb's Go-side
worker pool — all incompatible with the `signal-safety(7)` contract.
Do not call any binding entry point from a signal handler; if a signal
handler must trigger encryption / decryption, post the work to a
regular thread (e.g. via `eventfd` / pipe-write) and let that thread
re-enter the binding.

## Error model

Every libitb entry point returns a structured `itb_status_t` enum value
plus a textual diagnostic accessible through the per-thread accessors
`itb_last_status()` and `itb_last_error()`:

```c
#include <itb.h>
#include <stdio.h>

uint8_t keybuf[32] = {0};
itb_mac_t *bad = NULL;
itb_status_t st = itb_mac_new("nonsense", keybuf, sizeof keybuf, &bad);
if (st != ITB_OK) {
    /* st == ITB_BAD_MAC */
    fprintf(stderr, "code=%d msg=%s\n", st, itb_last_error());
}
```

The structural status code is the authoritative attribution for any
failing call; the textual diagnostic is decorative and survives only
until the next libitb call on the same thread. `itb_last_error()`
never returns `NULL` — first-call-with-no-error returns the empty
string `""`.

Empty plaintext / ciphertext is rejected by libitb itself with
`ITB_ENCRYPT_FAILED` (the Go-side `Encrypt128` / `Decrypt128` family
returns "itb: empty data" before any work). The C binding propagates
the rejection verbatim — pass at least one byte.

The `itb_encryptor_import` path additionally captures the offending
JSON field name on `ITB_EASY_MISMATCH`; retrieve it via
`itb_easy_last_mismatch_field(out, cap, &out_len)` (two-call probe,
NUL-stripped output, empty string when the most recent failure was not
a mismatch).

### Status codes

Mirror the constants in `cmd/cshared/internal/capi/errors.go`
bit-identically.

| Constant | Numeric | Meaning |
|---|---|---|
| `ITB_OK` | 0 | Success — the only non-failure return value |
| `ITB_BAD_HASH` | 1 | Unknown hash primitive name |
| `ITB_BAD_KEY_BITS` | 2 | ITB key width invalid for the chosen primitive |
| `ITB_BAD_HANDLE` | 3 | FFI handle invalid or already freed |
| `ITB_BAD_INPUT` | 4 | Generic shape / range / domain violation on a call argument |
| `ITB_BUFFER_TOO_SMALL` | 5 | Output buffer cap below required size; probe-then-allocate idiom |
| `ITB_ENCRYPT_FAILED` | 6 | Encrypt path raised on the Go side (rare; structural / OOM / empty input) |
| `ITB_DECRYPT_FAILED` | 7 | Decrypt path raised on the Go side (corrupt ciphertext shape) |
| `ITB_SEED_WIDTH_MIX` | 8 | Seeds passed to one call do not share the same native hash width |
| `ITB_BAD_MAC` | 9 | Unknown MAC name or key-length violates the primitive's `min_key_bytes` |
| `ITB_MAC_FAILURE` | 10 | MAC verification failed — tampered ciphertext or wrong MAC key |
| `ITB_EASY_CLOSED` | 11 | Easy Mode encryptor call after `itb_encryptor_close` |
| `ITB_EASY_MALFORMED` | 12 | Easy Mode `import` blob fails JSON parse / structural check |
| `ITB_EASY_VERSION_TOO_NEW` | 13 | Easy Mode blob version field higher than this build supports |
| `ITB_EASY_UNKNOWN_PRIMITIVE` | 14 | Easy Mode blob references a primitive this build does not know |
| `ITB_EASY_UNKNOWN_MAC` | 15 | Easy Mode blob references a MAC this build does not know |
| `ITB_EASY_BAD_KEY_BITS` | 16 | Easy Mode blob's `key_bits` invalid for its primitive |
| `ITB_EASY_MISMATCH` | 17 | Easy Mode blob disagrees with the receiver on `primitive` / `key_bits` / `mode` / `mac`; field name via `itb_easy_last_mismatch_field` |
| `ITB_EASY_LOCKSEED_AFTER_ENCRYPT` | 18 | `itb_encryptor_set_lock_seed(e, 1)` called after the first encrypt — must precede the first ciphertext |
| `ITB_BLOB_MODE_MISMATCH` | 19 | Native Blob importer received a Single blob into a Triple receiver (or vice versa) |
| `ITB_BLOB_MALFORMED` | 20 | Native Blob payload fails JSON parse / magic / structural check |
| `ITB_BLOB_VERSION_TOO_NEW` | 21 | Native Blob version field higher than this libitb build supports |
| `ITB_BLOB_TOO_MANY_OPTS` | 22 | Native Blob export opts mask carries unsupported bits |
| `ITB_STREAM_TRUNCATED` | 23 | Streaming AEAD transcript truncated before the terminator chunk; surfaced by the binding's stream loop helpers |
| `ITB_STREAM_AFTER_FINAL` | 24 | Streaming AEAD transcript carries chunk bytes after the terminator; surfaced by the binding's stream loop helpers |
| `ITB_INTERNAL` | 99 | Generic "internal" sentinel for paths the caller cannot recover from at the binding layer |

## Constraints

- **C17 minimum.** The header uses `_Static_assert`-free declarations
  and the source uses standard C17 idioms (`stdint.h` typedefs,
  designated initialisers, compound literals). GCC ≥ 10 and Clang ≥ 13
  meet the baseline.
- **Single public header.** All consumer-visible declarations live in
  `include/itb.h`; the layout-internal `src/internal.h` is
  intentionally hidden.
- **Static archive only.** The binding ships `build/libitb_c.a`; no
  shared-library variant is produced. Consumers link the archive
  alongside `libitb.so`.
- **No external runtime deps beyond libc + libitb.so.** The public
  surface uses only `<stddef.h>` + `<stdint.h>`; the implementation
  uses `<stdlib.h>` + `<string.h>` + `<assert.h>` plus the C11
  `_Thread_local` storage-class for the per-thread last-error buffer
  (no `pthread` link dependency — the dynamic linker's TLS allocator
  resolves storage on first thread access). The
  [Check](https://libcheck.github.io/check/) framework is required only
  for the test runner, not for consumer applications.
- **Frozen C ABI.** The `ITB_*` exports in `dist/<os>-<arch>/libitb.h`
  define the contract; the binding does not extend or reshape them.
- **No `dlopen`.** Symbols are bound at link time. Consumers wanting
  runtime FFI loading (different `libitb.so` per environment) can wrap
  this binding's static archive in their own `dlopen` shim.

## API Overview

All public declarations live in `include/itb.h`. The surface is
organised by concern below; every function returns `itb_status_t`
(typedef'd integer status code) or a small fixed-width primitive type.
Output strings follow a uniform `(char *out, size_t cap, size_t *out_len)`
probe-then-fill convention.

### Library metadata

| Function | Purpose |
|---|---|
| `itb_status_t itb_version(char *out, size_t cap, size_t *out_len)` | Version string `"<major>.<minor>.<patch>"` |
| `int itb_max_key_bits(void)` | Max supported ITB key width in bits |
| `int itb_channels(void)` | Number of native channel slots |
| `int itb_header_size(void)` | Current chunk header size (tracks `itb_set_nonce_bits`) |
| `itb_status_t itb_parse_chunk_len(const void *header, size_t header_len, size_t *out_total)` | Parse chunk header, return total on-wire chunk length |
| `int itb_hash_count(void)` / `itb_status_t itb_hash_name(int i, ...)` / `int itb_hash_width(int i)` | Hash catalogue accessors |
| `int itb_mac_count(void)` / `itb_status_t itb_mac_name(int i, ...)` / `int itb_mac_key_size(int i)` / `int itb_mac_tag_size(int i)` / `int itb_mac_min_key_bytes(int i)` | MAC catalogue accessors |
| `itb_status_t itb_last_status(void)` | Per-thread last status code |

### Process-wide configuration

| Function | Purpose |
|---|---|
| `itb_status_t itb_set_bit_soup(int mode)` / `int itb_get_bit_soup(void)` | Bit Soup mode toggle |
| `itb_status_t itb_set_lock_soup(int mode)` / `int itb_get_lock_soup(void)` | Lock Soup mode toggle |
| `itb_status_t itb_set_lock_batch(int mode)` / `int itb_get_lock_batch(void)` | Lock Batch mode toggle (performance variant of Lock Soup; recommended under the PRF assumption; symmetric; inert unless Lock Soup is engaged) |
| `itb_status_t itb_set_max_workers(int n)` / `int itb_get_max_workers(void)` | Worker pool size cap |
| `itb_status_t itb_set_nonce_bits(int n)` / `int itb_get_nonce_bits(void)` | Nonce width (128 / 256 / 512) |
| `itb_status_t itb_set_barrier_fill(int n)` / `int itb_get_barrier_fill(void)` | Barrier-fill factor (1, 2, 4, 8, 16, 32) |
| `int64_t itb_set_memory_limit(int64_t limit)` | Go runtime heap soft limit; negative = query only |
| `int itb_set_gc_percent(int pct)` | Go GC trigger percentage; negative = query only |

### Seeds (`itb_seed_t`)

| Function | Purpose |
|---|---|
| `itb_status_t itb_seed_new(const char *hash_name, int key_bits, itb_seed_t **out)` | CSPRNG-fresh seed |
| `itb_status_t itb_seed_from_components(...)` | Reconstruct seed from explicit components |
| `void itb_seed_free(itb_seed_t *s)` | Release seed handle |
| `itb_status_t itb_seed_width(const itb_seed_t *s, int *out_width)` | Native digest width |
| `itb_status_t itb_seed_hash_name(...)` / `itb_seed_hash_key(...)` / `itb_seed_components(...)` | Introspection accessors |
| `itb_status_t itb_seed_attach_lock_seed(itb_seed_t *noise, const itb_seed_t *lock)` | Bind a lock seed onto a noise seed |

### MAC handles (`itb_mac_t`)

| Function | Purpose |
|---|---|
| `itb_status_t itb_mac_new(const char *mac_name, const uint8_t *key, size_t key_len, itb_mac_t **out)` | Construct MAC handle |
| `void itb_mac_free(itb_mac_t *m)` | Release MAC handle |

### Low-level cipher (free functions)

| Function | Purpose |
|---|---|
| `itb_status_t itb_encrypt(noise, data, start, plaintext, ..., out)` | Single Message encrypt |
| `itb_status_t itb_decrypt(noise, data, start, ciphertext, ..., out)` | Single Message decrypt |
| `itb_status_t itb_encrypt_auth(noise, data, start, mac, ...)` / `itb_decrypt_auth(...)` | MAC-authenticated counterparts |
| `itb_status_t itb_encrypt_triple(noise, d1, d2, d3, s1, s2, s3, ...)` / `itb_decrypt_triple(...)` | Triple Ouroboros (7 seeds) |
| `itb_status_t itb_encrypt_auth_triple(...)` / `itb_decrypt_auth_triple(...)` | Triple Ouroboros MAC-authenticated |
| `void itb_buffer_free(uint8_t *buf)` | Free output buffer allocated by an encrypt / decrypt call |

### Easy Mode encryptor (`itb_encryptor_t`)

| Function | Purpose |
|---|---|
| `itb_status_t itb_encryptor_new(const char *primitive, int key_bits, const char *mac, const char *mode, itb_encryptor_t **out)` | Single-primitive constructor |
| `itb_status_t itb_encryptor_new_mixed(...)` / `itb_encryptor_new_mixed3(...)` | Mixed-primitive Single / Triple constructors |
| `itb_status_t itb_encryptor_encrypt(...)` / `itb_encryptor_decrypt(...)` | Cipher entry points |
| `itb_status_t itb_encryptor_encrypt_auth(...)` / `itb_encryptor_decrypt_auth(...)` | MAC-authenticated cipher entry points |
| `itb_status_t itb_encryptor_set_nonce_bits / _barrier_fill / _bit_soup / _lock_soup / _lock_batch / _lock_seed / _chunk_size (e, n)` | Per-instance overrides |
| `itb_status_t itb_encryptor_primitive / _mac_name / _primitive_at / _key_bits / _mode / _seed_count / _nonce_bits / _header_size / _has_prf_keys / _is_mixed (...)` | Configuration accessors |
| `itb_status_t itb_encryptor_parse_chunk_len(...)` | Per-instance chunk-length parser |
| `itb_status_t itb_encryptor_prf_key(e, slot, ...)` / `itb_encryptor_mac_key(e, ...)` / `itb_encryptor_seed_components(...)` | Key-material accessors |
| `itb_status_t itb_encryptor_export(...)` / `itb_encryptor_import(e, blob, blob_len)` | State-blob persistence |
| `itb_status_t itb_easy_peek_config(...)` / `itb_easy_last_mismatch_field(...)` | Pre-import discriminator + mismatch field name |
| `itb_status_t itb_encryptor_close(itb_encryptor_t *e)` / `void itb_encryptor_free(itb_encryptor_t *e)` | Close + release |

### Streaming AEAD (free-function bridges and per-encryptor variants)

| Function | Purpose |
|---|---|
| `itb_status_t itb_stream_encrypt / _decrypt (seeds, callbacks, ...)` | Single-primitive Low-Level stream (No MAC) |
| `itb_status_t itb_stream_encrypt_triple / _decrypt_triple (...)` | Triple Low-Level stream (No MAC) |
| `itb_status_t itb_stream_encrypt_auth / _decrypt_auth (seeds, mac, ...)` | Single Low-Level Streaming AEAD |
| `itb_status_t itb_stream_encrypt_auth_triple / _decrypt_auth_triple (...)` | Triple Low-Level Streaming AEAD |
| `itb_status_t itb_encryptor_stream_encrypt_auth(e, ...)` / `itb_encryptor_stream_decrypt_auth(e, ...)` | Easy Mode Streaming AEAD |
| `typedef int (*itb_stream_read_fn)(...)` / `typedef int (*itb_stream_write_fn)(...)` | User-supplied IO callbacks |

### Native Blob (`itb_blob128_t` / `itb_blob256_t` / `itb_blob512_t`)

The three blob types are declared uniformly through the
`ITB_DECLARE_BLOB_API(width, ...)` macro family. Per width the surface
covers: `itb_blob<width>_new` / `_free`, `_set_key` / `_set_components`
/ `_set_mac_key` / `_set_mac_name`, the matching `_get_*` introspection
accessors, `_export` / `_export_triple` / `_import` / `_import_triple`,
and `_width` / `_mode`.

### Wrapper (format-deniability outer cipher)

| Function | Purpose |
|---|---|
| `itb_status_t itb_wrapper_key_size(itb_wrapper_cipher_t cipher, size_t *out)` | Key size in bytes for a given cipher |
| `itb_status_t itb_wrapper_nonce_size(itb_wrapper_cipher_t cipher, size_t *out)` | Wire nonce size in bytes |
| `itb_status_t itb_wrapper_generate_key(itb_wrapper_cipher_t cipher, uint8_t *out, size_t out_cap)` | CSPRNG-fresh wrapper key |
| `itb_status_t itb_wrapper_derive_key(itb_wrapper_cipher_t cipher, const uint8_t *master, size_t master_len, uint8_t **out_key, size_t *out_key_len)` | Deterministic wrapper key from a master secret (>= 32 bytes, e.g. an ML-KEM shared secret) |
| `itb_status_t itb_wrap(cipher, key, blob, ...)` / `itb_unwrap(cipher, key, wire, ...)` | Single Message Wrap / Unwrap |
| `itb_status_t itb_wrap_in_place(cipher, key, buf, ...)` / `itb_unwrap_in_place(...)` | In-place Wrap / Unwrap |
| `itb_status_t itb_wrap_stream_writer_new(cipher, key, itb_wrap_stream_writer_t **out)` | Open a streaming wrap writer |
| `itb_status_t itb_wrap_stream_writer_update(w, src, src_len, out, out_cap, ...)` / `void itb_wrap_stream_writer_free(w)` | Streaming wrap update / close |
| `itb_status_t itb_unwrap_stream_reader_new(cipher, key, wire_nonce, ...)` / `..._update(...)` / `void ..._free(r)` | Streaming unwrap reader |

The wrapper cipher enum (`itb_wrapper_cipher_t`) covers

`ITB_WRAPPER_CIPHER_AREION_256`, `ITB_WRAPPER_CIPHER_AREION_512`,
`ITB_WRAPPER_CIPHER_BLAKE2B_256`, `ITB_WRAPPER_CIPHER_BLAKE2B_512`,
`ITB_WRAPPER_CIPHER_BLAKE2S`, `ITB_WRAPPER_CIPHER_BLAKE3`,
`ITB_WRAPPER_CIPHER_AES_128_CTR`, `ITB_WRAPPER_CIPHER_SIPHASH24`,
`ITB_WRAPPER_CIPHER_CHACHA20`, etc...

### Error handling

| Symbol | Purpose |
|---|---|
| `typedef enum itb_status` | 24 named status codes plus `ITB_STATUS_INTERNAL` (99) |
| `itb_status_t itb_last_status(void)` | Per-thread last-error retrieval |

Hash names are sourced from `itb_hash_*`; MAC names (`kmac256`,
`hmac-sha256`, `hmac-blake3`) from `itb_mac_*`.
