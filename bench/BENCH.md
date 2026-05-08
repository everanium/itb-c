# ITB C Binding - Easy Mode Benchmark Results

Throughput (MB/s) of `itb_encryptor_encrypt` / `itb_encryptor_decrypt`
/ `itb_encryptor_encrypt_auth` / `itb_encryptor_decrypt_auth` over the
libitb c-shared library through the C binding's static-library +
`libitb.so` link surface. Single + Triple Ouroboros at 1024-bit ITB
key width on a 16 MiB non-deterministic-fill payload, four ops per
primitive. The MAC slot is bound to **HMAC-BLAKE3** — the lightest
authenticated-mode overhead among the three shipping MACs (the
`encrypt_auth` row sits within a few percent of the matching `encrypt`
row).

The harness lives under [.](.) — see [README.md](README.md) for
invocation, environment variables, and the per-case output format.
The default measurement window is 5 seconds per case
(`ITB_BENCH_MIN_SEC=5`), wide enough to absorb the cold-cache /
warm-up transient that distorts shorter windows on the 16 MiB encrypt
/ decrypt path.

Reproduction (from `bindings/c/`):

```bash
make bench
./run_bench.sh                  # full 4-pass canonical sweep
ITB_LOCKSEED=1 ./run_bench.sh   # equivalent to passes 3 + 4 alone
```

## FFI overhead vs. native Go

The C path adds a static-library jump into the binding wrapper, the C
ABI crossing into Go via `libitb.so`, and a result-copy from the
c-shared output buffer back into a caller-owned buffer returned by
`itb_buffer_free`. The encryptor caches a per-instance output buffer
and pre-allocates from a 1.25× upper bound on the empirical ITB
ciphertext-expansion factor (≤ 1.155 across every primitive / mode /
nonce / payload-size combination) so the hot loop avoids the
size-probe round-trip the process-global FFI helpers use. The cached
bytes are zeroed on grow and on `itb_encryptor_close` /
`itb_encryptor_free`, so residual ciphertext / plaintext cannot linger
in heap garbage between cipher calls.

The numbers below ride the default build (no opt-out tags). On hosts
without AVX-512+VL the Go side automatically nil-routes the 4-lane
batched chain-absorb arm so the per-pixel hash falls through to the
upstream stdlib asm via the single `Func` — see the build-tag table
in [`../README.md`](../README.md) for the `-tags=purego` /
`-tags=noitbasm` opt-outs.

## Intel Core i7-11700K (16 HT, native Linux, c-shared mode)

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 186 | 285 | 182 | 264 |
| **Areion-SoEM-512** | 512 | PRF | 202 | 297 | 185 | 272 |
| **SipHash-2-4** | 128 | PRF | 149 | 191 | 139 | 182 |
| **AES-CMAC** | 128 | PRF | 186 | 261 | 171 | 241 |
| **BLAKE2b-512** | 512 | PRF | 125 | 167 | 122 | 161 |
| **BLAKE2b-256** | 256 | PRF | 93 | 108 | 90 | 105 |
| **BLAKE2s** | 256 | PRF | 99 | 117 | 88 | 102 |
| **BLAKE3** | 256 | PRF | 105 | 139 | 116 | 140 |
| **ChaCha20** | 256 | PRF | 108 | 128 | 102 | 125 |
| **Mixed** | 256 | PRF | 109 | 126 | 103 | 121 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 249 | 323 | 236 | 301 |
| **Areion-SoEM-512** | 512 | PRF | 280 | 336 | 248 | 308 |
| **SipHash-2-4** | 128 | PRF | 186 | 205 | 170 | 194 |
| **AES-CMAC** | 128 | PRF | 241 | 275 | 221 | 272 |
| **BLAKE2b-512** | 512 | PRF | 163 | 176 | 148 | 166 |
| **BLAKE2b-256** | 256 | PRF | 106 | 112 | 101 | 110 |
| **BLAKE2s** | 256 | PRF | 107 | 120 | 110 | 118 |
| **BLAKE3** | 256 | PRF | 141 | 152 | 130 | 145 |
| **ChaCha20** | 256 | PRF | 124 | 132 | 118 | 130 |
| **Mixed** | 256 | PRF | 125 | 135 | 118 | 131 |

## Intel Core i7-11700K (16 HT, native Linux, c-shared mode, LockSeed mode)

The dedicated lockSeed channel (`itb_encryptor_set_lock_seed(e, 1)` /
`ITB_LOCKSEED=1`) auto-couples bit-soup + lock-soup on the
on-direction. Numbers below run with all three overlays active.

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 60 | 71 | 62 | 70 |
| **Areion-SoEM-512** | 512 | PRF | 50 | 56 | 50 | 53 |
| **SipHash-2-4** | 128 | PRF | 63 | 69 | 64 | 72 |
| **AES-CMAC** | 128 | PRF | 74 | 83 | 70 | 81 |
| **BLAKE2b-512** | 512 | PRF | 46 | 49 | 44 | 48 |
| **BLAKE2b-256** | 256 | PRF | 41 | 44 | 40 | 44 |
| **BLAKE2s** | 256 | PRF | 42 | 46 | 42 | 46 |
| **BLAKE3** | 256 | PRF | 42 | 42 | 42 | 45 |
| **ChaCha20** | 256 | PRF | 45 | 49 | 36 | 41 |
| **Mixed** | 256 | PRF | 45 | 51 | 45 | 50 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 58 | 63 | 59 | 63 |
| **Areion-SoEM-512** | 512 | PRF | 52 | 54 | 50 | 53 |
| **SipHash-2-4** | 128 | PRF | 66 | 71 | 66 | 68 |
| **AES-CMAC** | 128 | PRF | 75 | 78 | 71 | 76 |
| **BLAKE2b-512** | 512 | PRF | 46 | 47 | 45 | 46 |
| **BLAKE2b-256** | 256 | PRF | 42 | 42 | 40 | 43 |
| **BLAKE2s** | 256 | PRF | 42 | 44 | 43 | 44 |
| **BLAKE3** | 256 | PRF | 43 | 43 | 41 | 42 |
| **ChaCha20** | 256 | PRF | 46 | 46 | 38 | 42 |
| **Mixed** | 256 | PRF | 45 | 50 | 47 | 48 |

## Notes

- The first row in every Single-Ouroboros pass typically shows a
  transient asymmetry between encrypt and decrypt. This is the
  cold-cache + first-iteration warmup absorbed imperfectly even at
  5-second windows; subsequent rows in the same pass run on warm
  caches and report symmetric encrypt-vs-decrypt numbers. Re-running
  the same primitive in isolation
  (`ITB_BENCH_FILTER=areion256 ITB_BENCH_MIN_SEC=20 ./bench/build/bench_single`)
  normalises the asymmetry.
- The LockSeed arms cap throughput in the 36-83 MB/s band because the
  dedicated lockseed slot auto-engages BitSoup + LockSoup; the bit-
  level split + per-chunk PRF-keyed bit-permutation overlay together
  dominate the per-byte cost. Within that band, AES-CMAC (128 native)
  leads at 70-83 MB/s and the 512-bit primitives sit at the floor near
  46-56 MB/s — wider hash output produces more per-pixel work and
  loses ground under the lockseed-mode multiplier.
- Triple Ouroboros exceeds Single Ouroboros throughput on most
  primitives in the no-LockSeed arms because the seven-seed split
  exposes additional internal parallelism opportunities to libitb's
  worker pool while the on-the-wire chunk count remains the same. The
  effect collapses under LockSeed mode where the per-chunk overlay
  cost dominates and the two arms converge to the same band.
- Bench cases run sequentially per pass; libitb's internal worker
  pool (`itb_set_max_workers(0)` → all CPUs) processes each case's
  chunk-level parallelism within the case's wall-clock window.
