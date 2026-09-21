# EVIDENCE — PHASE 5: Honest benchmarks (measured)

**Status: DONE.** Date: 2026-09-18 (HDR extension 2026-09-19). Directory:
`cpp/bench/benchmarks/`.

## Method (anti-cheat)

- Every iteration decodes/encodes into a FRESH output and feeds a volatile
  sink (anti dead-code elimination); NO memoization of the measured case.
- Latency via timed batches (batch size declared in every JSON) to remove
  clock-granularity bias for sub-100 ns operations.
- Dev mode (fast) and final mode (held-out sizes) — both executed and
  published. Nearest-rank percentiles over the real samples; since 2026-09-19
  percentiles are produced by the own HDR histogram (cross-checked against
  HdrHistogram_c, see `cpp/evidence/10-latency-elite/PHASE1/`).
- Numbers only MEASURED on this host (MSVC cl 14.50 /O2, Windows x64; CPython
  3.14 stdlib json for the JSON comparison).

## Final results (exact figures in benchmarks/*.json)

| Benchmark | p50 | p99 | p99.9 | p99.99 |
|---|---|---|---|---|
| ITCH 5.0 decode (C++) | 16 ns | 20 ns | — | — |
| SBE Binance decode (C++) | 83 ns | 182 ns | **326 ns** | **966 ns** |
| False sharing: same cache line vs separate | 1.03 ns vs 0.19 ns | — | — | — |
| Multicast publish (29 B) | 2.682 ns | 95.146 ns | — | — |
| JSON depth decode (Python stdlib) | 1.500 ns | 4.900 ns | — | — |

Honest decode comparison SBE vs current JSON: 83 ns (SBE C++) vs 1.500 ns
(JSON Python stdlib) p50 per message. Declared limit: the JSON figure covers
json.loads only; the string-to-decimal conversion and book application (also
paid by the current JSON path) are not included — the comparison is reported
separately, never as a single misleading ratio.

## Evidence files (measured, never estimated)

- `cpp/bench/benchmarks/bench_*_final.json` and `bench_*_final_hdr.json`
- (dev mode: `bench_*_dev.json` / `bench_*_dev_hdr.json` in the same folder)

Reproducible with `cpp/bench/run_benchmarks.ps1 -Mode both`.
