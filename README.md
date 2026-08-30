# ITB C Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin proxy over the libitb shared library's `ITB_Triple_*` surface
(`cmd/cshared`). C11 static (`libitb_c.a`) + shared (`libitb_c.so`)
library that **links against `libitb.so` at compile time**
(`-litb_c -litb` with an embedded RPATH) — no runtime symbol loading.
Every hash-name / MAC-name / cipher-name / profile-name is an opaque
string passed through to Go for validation; the binding carries no
ITB construction logic. The public surface is one `itb_pipeline`
handle (init / open / rekey / free, Single Message encrypt / decrypt,
whole-buffer stream pumps, incremental `itb_stream` sessions with
write / end / read), an `itb_opts` query-string builder,
`itb_register_profile`, and the Go runtime knobs.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go gcc make
```

Generic Linux: a Go toolchain, a C11 compiler (gcc or clang), and GNU
make. macOS: the same via Xcode command-line tools; libitb builds as
`libitb.dylib`. Windows: MinGW-w64 or clang against `libitb.dll`.

## Build the shared library

The convenience driver builds `libitb.so`, the C library, and every
test binary in one step:

```bash
./bindings/c/build.sh
```

Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
cd bindings/c && make all
```

## Add to a C / C++ project

Compile against the public header and link the static archive plus
the underlying `libitb.so`:

```bash
cc -std=c11 -I/path/to/bindings/c/include myapp.c \
    /path/to/bindings/c/build/libitb_c.a \
    -L/path/to/dist/linux-amd64 -Wl,-rpath,/path/to/dist/linux-amd64 \
    -litb
```

The header is C++-aware (`extern "C"` block guarded by
`__cplusplus`), so the same archive serves C and C++ consumers
without a separate wrapper.

## Usage example

```c
#include <itb.h>

itb_pipeline *sender = NULL, *receiver = NULL;
itb_status st = itb_pipeline_init("singlemsg-triple-mac-v1", NULL, &sender);
/* st != ITB_STATUS_OK → consult itb_last_error() */
st = itb_pipeline_open("singlemsg-triple-mac-v1",
                       itb_pipeline_blob(sender),
                       itb_pipeline_blob_len(sender),
                       NULL, NULL, 0, NULL, 0, &receiver);

uint8_t *wire = NULL; size_t wire_len = 0;
st = itb_pipeline_encrypt_message(sender, (const uint8_t *)"data", 4,
                                  &wire, &wire_len);

uint8_t *plain = NULL; size_t plain_len = 0;
st = itb_pipeline_decrypt_message(receiver, wire, wire_len,
                                  &plain, &plain_len);

itb_bytes_free(wire);
itb_bytes_free(plain);
itb_pipeline_free(receiver);
itb_pipeline_free(sender);
```

`itb_opts` overrides the profile default per call (chunk size, outer
cipher, parallax on/off, wrapper on/off, MAC name, palette); every
setter goes through `itb_opts_set(opts, key, value)`:

```c
itb_opts *opts = itb_opts_new();
itb_opts_set(opts, "chunkSize", "65536");
itb_opts_set(opts, "withWrapper", "false");
itb_pipeline_init("singlemsg-triple-mac-v1", opts, &sender);
itb_pipeline_open("singlemsg-triple-mac-v1",
                  itb_pipeline_blob(sender), itb_pipeline_blob_len(sender),
                  opts, NULL, 0, NULL, 0, &receiver);
itb_opts_free(opts);
```

`itb_pipeline_rekey` rotates the parallax + wrapper masters
mid-session (the eight ITB seeds and MAC key are fixed for the
session lifetime by design); the receiver picks up the new masters
through a fresh `itb_pipeline_blob(sender)` handshake:

```c
uint8_t perm[32] = { /* fresh */ }, wrap[32] = { /* fresh */ };
itb_pipeline_rekey(sender, perm, sizeof perm, wrap, sizeof wrap);
itb_pipeline_open("singlemsg-triple-mac-v1",
                  itb_pipeline_blob(sender), itb_pipeline_blob_len(sender),
                  NULL, NULL, 0, NULL, 0, &receiver);
```

`itb_pipeline_encrypt_stream_one_shot` /
`itb_pipeline_decrypt_stream_one_shot` put a whole in-memory payload
through the stream chain in a single call. For bounded-memory
streaming, `itb_pipeline_encrypt_stream_pump` /
`itb_pipeline_decrypt_stream_pump` move a whole buffer through an
incremental session; the explicit `itb_pipeline_encrypt_stream_begin`
/ `itb_pipeline_decrypt_stream_begin` sessions expose
`itb_stream_write` / `itb_stream_end` / `itb_stream_read` for
caller-driven loops.

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string surfaces as a non-OK `itb_status` with
the diagnostic available via `itb_last_error()`.

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable at
libitb load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass `-1` to query without
changing. Long-running or allocation-heavy workloads (benchmarks,
bulk encryption) should set both — without a soft cap + aggressive GC
the Go scratch heap grows unboundedly under allocation churn:

```c
itb_set_memory_limit(512LL << 20); /* 512 MiB soft cap */
itb_set_gc_percent(20);            /* aggressive GC */
```

## Testing

```bash
./bindings/c/run_tests.sh
```

The harness builds `libitb.so` + the C library, compiles every
`tests/test_*.c` to its own standalone executable under
`tests/build/`, and runs each in turn; per-process isolation gives
every test a fresh libitb global state. The suite covers Single
Message round trips per shipped profile, stream pumps, incremental
sessions with pathological batch sizes, tampered-wire failure
stickiness, mid-flight cancellation, rekey, profile registration,
opts-builder encoding, and error mapping — surface parity checks; the
deep suite lives in Go under the shipped tree. Override the compiler
via `CC=clang ./bindings/c/run_tests.sh`.

## Sanitizer runs

```bash
cd bindings/c
make test-asan       # test suite under AddressSanitizer
make test-ubsan      # test suite under UndefinedBehaviorSanitizer
make test-valgrind   # test suite under valgrind --leak-check=full
```

The sanitizer targets rebuild the library + tests into separate
build directories (`build/asan`, `build/ubsan`) so instrumented and
plain objects never mix. `test-valgrind` requires valgrind to be able
to read the host `ld.so` symbols (on some distributions this needs
the glibc debug-symbol package); where host symbols are unavailable,
the same binaries run under valgrind inside a stock `ubuntu:24.04`
container with `valgrind` + `libc6-dbg` installed and the repository
bind-mounted at its host path (the embedded RPATH resolves
`libitb.so` unchanged). `tests/valgrind.supp` silences memcheck noise
whose faulting frame lies inside `libitb.so` — the Go runtime manages
its own stacks and heap in ways memcheck cannot model; errors in the
binding's own C frames are never suppressed.

## Benchmarking

```bash
./bindings/c/run_bench.sh
```

Micro-benches: `message` (EncryptMessage) and `stream_pump`
(encrypt stream pump) throughput at 1 KiB / 64 KiB / 1 MiB / 16 MiB,
reported as an MB/s table on stdout. The runner exports
`ITB_GOMEMLIMIT=512MiB` + `ITB_GOGC=20` defaults (respecting caller
overrides) and the bench binaries apply the same caps
programmatically.

## eitb utility

A small CLI under `bindings/c/eitb/` mirrors the shipped Go
`tools/eitb` scope for shell smoke tests:

```bash
cd bindings/c/eitb && make
./eitb version
./eitb hashes
./eitb encrypt singlemsg-triple-mac-v1 in.bin out.bin   # blob hex on stderr
./eitb decrypt singlemsg-triple-mac-v1 <blob-hex> out.bin back.bin
```

## Limitations

- The binding wraps the Triple Pipeline surface only. The Low-Level
  seed / MAC / blob / wrapper / parallax APIs are not exposed — use
  the shipped Go core for those.
- Streaming-decrypt caveat: chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication.
- The `itb_last_error()` text is process-global last-write-wins on
  the Go side; fetch it immediately after the failing call. The
  status code is always attributable.
- `itb_pipeline_rekey` must not run concurrently with cipher calls or
  open stream sessions on the same Pipeline.
- Handles are freed exactly once (`itb_pipeline_free` /
  `itb_stream_free`, both NULL-safe); a stream session must not
  outlive its Pipeline.
