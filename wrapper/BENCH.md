# ITB Format-Deniability Wrapper Benchmark Results — C Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

The wrapper layer prefixes a fresh CSPRNG nonce and XORs every byte of an ITB ciphertext under one of outer keystream ciphers, one per PRF-grade ITB registry primitive in CTR mode. The keystream construction is delegated libitb-side to the `ctr` package. The wire format becomes `nonce || keystream-XOR(bytestream)`, indistinguishable from any generic stream-cipher payload by surface pattern; ITB's own content-deniability is unchanged.

The numbers below isolate the **outer cipher cost** that the wrapper layer adds on top of ITB. Two test scopes:

* **Wrapper Only** — 16 MiB random buffer, no ITB call. Pure outer cipher round-trip throughput. The `WrapInPlace` row mutates the caller's buffer (no output-buffer allocation); the `Wrap` row allocates a fresh output buffer per call.
* **Full ITB + wrapper** — encrypt and decrypt are timed **separately** (split sub-benches `…/encrypt` and `…/decrypt`) so the per-direction breakdown is visible. Both Single Ouroboros and Triple Ouroboros are reported. Single-message benches process a 16 MiB plaintext under one encrypt / wrap call (or one unwrap / decrypt call). Streaming benches process a 64 MiB plaintext through 16 MiB chunks via either ITB's callback-driven Streaming AEAD API or a User-Driven Loop emitting framed chunks through the wrap-stream writer.

The wrapper bench covers all outer ciphers — each in CTR mode.

### Concurrency note — outer cipher throughput on big-iron

Outer-cipher overhead on a 16 HT host with hardware AES-NI is effectively zero — the AES-CTR keystream finishes well ahead of every ITB-encrypt slot, and the `WrapInPlace` path avoids output-buffer allocation. **On larger Triple Ouroboros hosts (e.g. AMD EPYC 9655P, 192 HT) the picture inverts for the non-AES outer ciphers**: ITB's per-pixel hashing scales across all available HT, while the wrapper's keystream XOR splits across up to 32 worker goroutines (`min(32, GOMAXPROCS, chunks)`) inside libitb for buffers at or above the 256 KiB threshold, each worker seeking its own keystream to its chunk offset via `ctr.NewAt`; buffers below the threshold run serially.

The C binding routes XOR through a single libitb FFI call; the parallelisation across up to 32 goroutines happens inside libitb for buffers at or above the 256 KiB threshold, so the binding adds only per-call FFI-crossing overhead on top of the parallel XOR.

## Binding asymmetry note

The C binding's Streaming No MAC arm covers the User-Driven Loop variant only — there is no IO-Driven Streaming No MAC writer / reader pair. The Streaming AEAD path covers IO-Driven for both Easy and Low-Level.

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

## Configuration

* Outer cipher path: all PRF-grade registry primitives, keystream built libitb-side via the `ctr` package.
* ITB primitive: Areion-SoEM-512.
* ITB seed width: 1024 bits.
* ITB cipher config: `NonceBits=128`, `BarrierFill=1`, `BitSoup=0`, `LockSoup=0` (minimum config so the outer cipher delta is not masked by per-pixel feature cost).
* `itb_set_max_workers(0)` (use every available HT for the per-pixel hash kernels).
* MAC factory: HMAC-BLAKE3, 32-byte CSPRNG key (where applicable).
* Single-message plaintext: 16 MiB random.
* Streaming plaintext: 64 MiB random; chunk size 16 MiB.
* Decrypt-only sub-benches refresh the working wire from a pristine copy each iteration via `memcpy`; the memcpy is included in the timed total. This overhead is small relative to ITB's Decrypt cost on this hardware.

Column abbreviations in the Full ITB + wrapper tables: **LL** = Low-Level, **Loop** = User-Driven Loop, **IO** = IO-Driven, **NoMAC** = No MAC, **MAC** = MAC Authenticated, **Enc** / **Dec** = encrypt / decrypt direction. All throughput is MB/s, rounded.

### Wrapper only round-trip (16 MiB plaintext, encrypt + decrypt timed together)

| Outer cipher | `Wrap` (alloc) MB/s | `WrapInPlace` (no output-buffer alloc) MB/s |
|---|---|---|
| **Areion-SoEM-256** | 1388 | 1677 |
| **Areion-SoEM-512** | 1403 | 1625 |
| **BLAKE2b-256** | 539 | 549 |
| **BLAKE2b-512** | 876 | 941 |
| **BLAKE2s** | 618 | 659 |
| **BLAKE3** | 1077 | 1158 |
| **AES-128-CTR** | 3002 | 4171 |
| **SipHash-2-4** | 1779 | 2302 |
| **ChaCha20** | 1797 | 2229 |

### Single Message — Single Ouroboros (16 MiB plaintext)

| Cipher | Easy NoMAC Enc | Easy NoMAC Dec | Easy MAC Enc | Easy MAC Dec | LL NoMAC Enc | LL NoMAC Dec | LL MAC Enc | LL MAC Dec |
|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 148 | 264 | 182 | 257 | 195 | 280 | 175 | 251 |
| **Areion-SoEM-512** | 196 | 278 | 182 | 258 | 198 | 281 | 178 | 253 |
| **BLAKE2b-256** | 178 | 238 | 163 | 223 | 177 | 238 | 158 | 216 |
| **BLAKE2b-512** | 190 | 262 | 174 | 244 | 190 | 264 | 171 | 240 |
| **BLAKE2s** | 175 | 242 | 166 | 226 | 180 | 242 | 163 | 220 |
| **BLAKE3** | 192 | 268 | 175 | 248 | 190 | 267 | 174 | 246 |
| **AES-128-CTR** | 202 | 289 | 185 | 269 | 203 | 289 | 181 | 260 |
| **SipHash-2-4** | 199 | 285 | 185 | 263 | 200 | 287 | 179 | 257 |
| **ChaCha20** | 196 | 285 | 182 | 260 | 196 | 275 | 178 | 251 |

### Single Message — Triple Ouroboros (16 MiB plaintext)

| Cipher | Easy NoMAC Enc | Easy NoMAC Dec | Easy MAC Enc | Easy MAC Dec | LL NoMAC Enc | LL NoMAC Dec | LL MAC Enc | LL MAC Dec |
|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 257 | 296 | 233 | 282 | 260 | 300 | 231 | 284 |
| **Areion-SoEM-512** | 257 | 301 | 236 | 283 | 259 | 294 | 235 | 279 |
| **BLAKE2b-256** | 222 | 249 | 203 | 238 | 215 | 246 | 208 | 242 |
| **BLAKE2b-512** | 245 | 270 | 222 | 260 | 242 | 278 | 228 | 272 |
| **BLAKE2s** | 224 | 258 | 204 | 242 | 228 | 257 | 211 | 249 |
| **BLAKE3** | 249 | 289 | 226 | 269 | 251 | 288 | 231 | 275 |
| **AES-128-CTR** | 268 | 316 | 241 | 294 | 271 | 315 | 246 | 300 |
| **SipHash-2-4** | 266 | 312 | 239 | 288 | 266 | 310 | 242 | 294 |
| **ChaCha20** | 261 | 304 | 237 | 286 | 265 | 307 | 244 | 297 |

### Streaming — Single Ouroboros (64 MiB plaintext, 16 MiB chunk size) — AEAD

| Cipher | AEAD Easy IO Enc | AEAD Easy IO Dec | AEAD LL IO Enc | AEAD LL IO Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 155 | 189 | 157 | 190 |
| **Areion-SoEM-512** | 157 | 192 | 157 | 191 |
| **BLAKE2b-256** | 144 | 171 | 145 | 170 |
| **BLAKE2b-512** | 152 | 184 | 151 | 182 |
| **BLAKE2s** | 146 | 174 | 147 | 172 |
| **BLAKE3** | 154 | 188 | 155 | 185 |
| **AES-128-CTR** | 158 | 198 | 161 | 195 |
| **SipHash-2-4** | 156 | 195 | 159 | 191 |
| **ChaCha20** | 159 | 195 | 159 | 191 |

### Streaming — Single Ouroboros (64 MiB plaintext, 16 MiB chunk size) — Non-AEAD (User-Driven Loop)

| Cipher | Easy Loop Enc | Easy Loop Dec | LL Loop Enc | LL Loop Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 176 | 242 | 177 | 220 |
| **Areion-SoEM-512** | 175 | 240 | 161 | 240 |
| **BLAKE2b-256** | 160 | 207 | 161 | 212 |
| **BLAKE2b-512** | 169 | 229 | 170 | 231 |
| **BLAKE2s** | 163 | 216 | 163 | 215 |
| **BLAKE3** | 173 | 235 | 173 | 235 |
| **AES-128-CTR** | 179 | 249 | 180 | 249 |
| **SipHash-2-4** | 177 | 246 | 178 | 246 |
| **ChaCha20** | 178 | 245 | 178 | 245 |

### Streaming — Triple Ouroboros (64 MiB plaintext, 16 MiB chunk size) — AEAD

| Cipher | AEAD Easy IO Enc | AEAD Easy IO Dec | AEAD LL IO Enc | AEAD LL IO Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 192 | 215 | 201 | 214 |
| **Areion-SoEM-512** | 201 | 216 | 201 | 215 |
| **BLAKE2b-256** | 180 | 192 | 180 | 191 |
| **BLAKE2b-512** | 193 | 206 | 192 | 206 |
| **BLAKE2s** | 181 | 193 | 180 | 193 |
| **BLAKE3** | 194 | 210 | 194 | 205 |
| **AES-128-CTR** | 208 | 223 | 207 | 223 |
| **SipHash-2-4** | 203 | 218 | 203 | 217 |
| **ChaCha20** | 203 | 218 | 201 | 218 |

### Streaming — Triple Ouroboros (64 MiB plaintext, 16 MiB chunk size) — Non-AEAD (User-Driven Loop)

| Cipher | Easy Loop Enc | Easy Loop Dec | LL Loop Enc | LL Loop Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 228 | 240 | 225 | 260 |
| **Areion-SoEM-512** | 227 | 261 | 225 | 258 |
| **BLAKE2b-256** | 199 | 224 | 197 | 223 |
| **BLAKE2b-512** | 216 | 247 | 213 | 243 |
| **BLAKE2s** | 200 | 229 | 201 | 227 |
| **BLAKE3** | 220 | 251 | 218 | 251 |
| **AES-128-CTR** | 234 | 271 | 233 | 268 |
| **SipHash-2-4** | 229 | 266 | 228 | 265 |
| **ChaCha20** | 228 | 266 | 228 | 265 |

This file is updated by re-running the reproduction command and pasting the bench output into the tables. Numbers above are rounded to MB/s.
