# FASE 2 evidence — false sharing / cache-line / lock-free SPSC, measured

Date: 2026-09-19. Reference patterns: LMAX Disruptor cache-line padding
(capture commit `c871ca49826a`, Apache-2.0) and the Aeron media-driver ring
design (capture `external-review/low-latency-reference/aeron`, design only).
All numbers below were produced by real runs on this host — nothing is
promised in advance and nothing is estimated.

## Static cache-line guarantees (`cpp/net/include/net/spsc_ring.hpp`)

The producer's `tail_` and the consumer's `head_` are both `alignas(64)`
`std::atomic<size_t>` members. The header proves at compile time that they
can never share a cache line (per-member alignment re-asserted with
`__alignof`/`__alignof__` member-expression intrinsics on MSVC and
GCC/Clang; the reasoning — 64-multiple offsets of distinct members ⇒
≥ 64 bytes apart — is documented in the header comment), and the runtime
value is asserted in the test below.

## Test suite (`cpp/net/tests/test_spsc.cpp`) — red → green

- Written first against the ring contract: **7/7 green** in the final run
  (see `FASE2/test_spsc_green.log` and the `spsc` phase inside
  `cpp/build.ps1 -Phase all`): cache-line separation runtime probe (asserts
  `index_separation_bytes() >= 64` on two instantiations), power-of-two
  capacity rounding, strict FIFO, explicit overflow (`try_push` returns
  false when full — nothing silently dropped, the pushed value survives),
  empty-pop semantics, index wraparound, single-slot capacity.
- The `spsc` phase runs in CI on Linux and Windows (same static asserts,
  both compilers).

## Measured benchmarks (final mode = held-out sizes; dev mode also recorded)

### False sharing — same line vs `alignas(64)` separated (2 threads × 1 counter each)

`cpp/bench/bench_false_sharing.cpp`. Counters are `volatile uint64_t`:
per-access memory operations the optimizer cannot coalesce (verified by the
correctness gate — both counters equal the exact increment count, printed in
the run log). Identical semantics in both layouts; only the cache-line
placement differs.

| Layout | p50 | p99 | p99.9 | p99.99 | throughput |
|---|---|---|---|---|---|
| Same cache line (false sharing) | 1.03 ns | 1.38 ns | 3.49 ns | 15.4 ns | 2.22 G ops/s |
| Separate `alignas(64)` lines | **0.19 ns** | **0.22 ns** | **0.95 ns** | **3.92 ns** | **10.38 G ops/s** |

Measured penalty of false sharing on this host: **5.4× at p50** and **4.7× in
throughput** (final mode; dev mode: 4.3× at p50). JSON:
`cpp/bench/benchmarks/bench_false_sharing_{dev,final}.json` +
`..._hdr.json`.

### SPSC ring, 1 producer / 1 consumer (`cpp/bench/bench_spsc.cpp`)

Ring: `net/spsc_ring.hpp`, ~1M usable slots, explicit-overflow policy
(producer retries on full; retries counted and reported). Final mode:
5 reps × 50M messages.

| Metric | p50 | p99 | p99.9 | p99.99 |
|---|---|---|---|---|
| push (incl. enqueue-timestamp clock read) | 48 ns | 67 ns | 202 ns | 331 ns |
| pop (pre-filled ring + concurrent feeder, no per-item telemetry) | 1 ns | 5 ns | 11 ns | 25 ns |
| end-to-end (consumer read − producer stamp, incl. queueing) | 9.49 ms | 31.9 ms | 37.1 ms | 38.1 ms |

Throughput: **21.4M msg/s** best (final), producer retries ≈ 0 (ring never
stayed full). The end-to-end distribution is dominated by queueing in a
bounded ring at ~21M msg/s — measured, not hidden; the push/pop rows isolate
the per-operation costs. JSON:
`cpp/bench/benchmarks/bench_spsc_{dev,final}.json` + `..._hdr.json`.

Notes (honesty): push samples include one `steady_clock` read per item (the
timestamp that makes e2e possible); the e2e consumer records each item into
the HDR histogram inline (per-item telemetry cost is part of the consumer
loop); the machine also runs unrelated production workloads, and occasional
OS scheduling shows up in the tails — the numbers above are exactly what was
measured under those conditions.

## Verification status

- `net/tests/test_spsc.cpp`: **7/7 green** (runs in `cpp/build.ps1 -Phase all`
  and `cpp/build.sh all`, both CI legs).
- Both benchmarks re-runnable with one command:
  `powershell -NoProfile -ExecutionPolicy Bypass -File cpp\bench\run_benchmarks.ps1 -Mode both`
  (Linux: `bash cpp/bench/run_benchmarks.sh both`).
- Artifact hashes: `MANIFEST_FASE2.md`.
