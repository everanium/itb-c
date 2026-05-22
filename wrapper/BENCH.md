# ITB Format-Deniability Wrapper Benchmark Results — C Binding

The wrapper layer prefixes a fresh CSPRNG nonce and XORs every byte of an ITB ciphertext under one of three outer keystream ciphers — AES-128-CTR (stdlib AES-NI on x86-64), ChaCha20 (RFC8439) (`golang.org/x/crypto/chacha20`), or SipHash-2-4 in CTR mode (`dchest/siphash` PRF + custom counter loop). The wire format becomes `nonce || keystream-XOR(bytestream)`, indistinguishable from any generic stream-cipher payload by surface pattern; ITB's own content-deniability is unchanged.

The numbers below isolate the **outer cipher cost** that the wrapper layer adds on top of ITB. Two test scopes:

* **Wrapper Only** — 16 MiB random buffer, no ITB call. Pure outer cipher round-trip throughput. The `WrapInPlace` row mutates the caller's buffer (zero allocation steady state); the `Wrap` row allocates a fresh output buffer per call.
* **Full ITB + wrapper** — encrypt and decrypt are timed **separately** (split sub-benches `…/encrypt` and `…/decrypt`) so the per-direction breakdown is visible. Both Single Ouroboros and Triple Ouroboros are reported. Single-message benches process a 16 MiB plaintext under one encrypt / wrap call (or one unwrap / decrypt call). Streaming benches process a 64 MiB plaintext through 16 MiB chunks via either ITB's callback-driven Streaming AEAD API or a User-Driven Loop emitting framed chunks through the wrap-stream writer.

### Concurrency note — outer cipher single-thread bottleneck on big-iron

Outer-cipher overhead on a 16 HT host with hardware AES-NI is effectively zero — the AES-CTR keystream finishes well ahead of every ITB-encrypt slot, and the `WrapInPlace` path adds no allocation pressure. **On larger Triple Ouroboros hosts (e.g. AMD EPYC 9655P, 192 HT) the picture inverts for the non-AES outer ciphers**: ITB's per-pixel hashing scales across all available HT, while the wrapper's keystream XOR runs single-threaded on one core. ChaCha20 (~700 MB/s peak on a single core via `x/crypto/chacha20`) and SipHash-CTR (~250–280 MB/s peak via the `dchest/siphash` PRF + 16-byte refill loop) become the bottleneck once ITB's Triple decrypt path approaches ~1 GB/s on big-iron. AES-128-CTR retains hardware acceleration on every HT thread the underlying goroutine lands on and stays out of the critical path even there.

The C binding's wrapper layer routes XOR through the libitb FFI — it neither parallelises the keystream itself nor offloads to a different thread pool. The single-thread ceiling is therefore the wrapper-layer bottleneck on hosts where ITB outpaces the chosen outer cipher.

## Reproduction

```sh
cd bindings/c
make bench
ITB_BENCH_MIN_SEC=5 ./bench/build/bench_wrapper
```

Filter examples:

```sh
ITB_BENCH_FILTER=BenchmarkWrapperOnlyInPlace ITB_BENCH_MIN_SEC=5 ./bench/build/bench_wrapper
ITB_BENCH_FILTER=BenchmarkMessageSingle/easy-nomac ITB_BENCH_MIN_SEC=5 ./bench/build/bench_wrapper
ITB_BENCH_FILTER=BenchmarkStreamingTriple ITB_BENCH_MIN_SEC=5 ./bench/build/bench_wrapper
```

Sub-bench count: **102**. (6 wrapper only round-trip + 24 Message Single + 24 Message Triple + 24 Streaming Single + 24 Streaming Triple. Each Streaming-* set: 4 modes × 3 ciphers × 2 directions; the C binding has no Streaming No MAC IO-Driven mode, replaced by User-Driven Loop variants.)

## Configuration

* Outer cipher path: AES-128-CTR (stdlib + AES-NI), ChaCha20 (RFC8439) (`golang.org/x/crypto/chacha20`), SipHash-2-4 in CTR mode (`dchest/siphash` + custom counter loop).
* ITB primitive: Areion-SoEM-512.
* ITB seed width: 1024 bits.
* ITB cipher config: `NonceBits=128`, `BarrierFill=1`, `BitSoup=0`, `LockSoup=0` (minimum config so the outer cipher delta is not masked by per-pixel feature cost).
* `itb_set_max_workers(0)` (use every available HT for the per-pixel hash kernels).
* MAC factory: HMAC-BLAKE3, 32-byte CSPRNG key (where applicable).
* Single-message plaintext: 16 MiB random.
* Streaming plaintext: 64 MiB random; chunk size 16 MiB.
* Decrypt-only sub-benches refresh the working wire from a pristine copy each iteration via `memcpy`; the memcpy is included in the timed total. This overhead is small relative to ITB's Decrypt cost on this hardware.

## Results

### Wrapper only round-trip (16 MiB plaintext, encrypt + decrypt timed together)

| Outer cipher | `Wrap` (alloc) MB/s | `WrapInPlace` (zero alloc) MB/s |
|---|---|---|
| **AES-128-CTR** | 2950 | **2900** |
| **ChaCha20** | 329 | **321** |
| **SipHash-CTR** | 274 | **268** |

### Single Message — Single Ouroboros (16 MiB plaintext)

| Mode | AES Enc | AES Dec | ChaCha Enc | ChaCha Dec | SipHash Enc | SipHash Dec |
|---|---|---|---|---|---|---|
| **Easy** No MAC | 187 | 270 | 148 | 190 | 140 | 178 |
| **Easy** MAC Authenticated | 181 | 250 | 139 | 180 | 131 | 169 |
| **Low-Level** No MAC | 192 | 267 | 148 | 190 | 139 | 176 |
| **Low-Level** MAC Authenticated | 175 | 246 | 135 | 178 | 131 | 167 |

### Single Message — Triple Ouroboros (16 MiB plaintext)

| Mode | AES Enc | AES Dec | ChaCha Enc | ChaCha Dec | SipHash Enc | SipHash Dec |
|---|---|---|---|---|---|---|
| **Easy** No MAC | 260 | 300 | 182 | 205 | 174 | 193 |
| **Easy** MAC Authenticated | 229 | 282 | 170 | 195 | 161 | 182 |
| **Low-Level** No MAC | 263 | 304 | 183 | 203 | 175 | 192 |
| **Low-Level** MAC Authenticated | 227 | 279 | 169 | 195 | 160 | 181 |

### Streaming — Single Ouroboros (64 MiB plaintext, 16 MiB chunk size)

| Mode | AES Enc | AES Dec | ChaCha Enc | ChaCha Dec | SipHash Enc | SipHash Dec |
|---|---|---|---|---|---|---|
| **Streaming AEAD Easy** IO-Driven | 143 | 167 | 116 | 134 | 110 | 126 |
| **Streaming AEAD Low-Level** IO-Driven | 143 | 155 | 117 | 132 | 110 | 124 |
| **Streaming Easy** No MAC, User-Driven Loop | 167 | 229 | 135 | 170 | 128 | 159 |
| **Streaming Low-Level** No MAC, User-Driven Loop | 169 | 232 | 136 | 172 | 129 | 159 |

### Streaming — Triple Ouroboros (64 MiB plaintext, 16 MiB chunk size)

| Mode | AES Enc | AES Dec | ChaCha Enc | ChaCha Dec | SipHash Enc | SipHash Dec |
|---|---|---|---|---|---|---|
| **Streaming AEAD Easy** IO-Driven | 181 | 192 | 141 | 147 | 134 | 136 |
| **Streaming AEAD Low-Level** IO-Driven | 182 | 193 | 142 | 149 | 134 | 142 |
| **Streaming Easy** No MAC, User-Driven Loop | 228 | 263 | 168 | 189 | 158 | 176 |
| **Streaming Low-Level** No MAC, User-Driven Loop | 229 | 264 | 167 | 187 | 156 | 174 |

This file is updated by re-running the reproduction command and pasting the bench output into the tables. Numbers above are rounded to MB/s.
