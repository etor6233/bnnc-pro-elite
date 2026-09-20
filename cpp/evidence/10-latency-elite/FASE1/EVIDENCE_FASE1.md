# FASE 1 evidence — HDR latency histogram in C++ + percentile integration

Date: 2026-09-19. Rule set: the campaign instruction §3 (nothing invented,
red → green, metrics only measured, evidence per step). Reference semantics:
HdrHistogram_c, captured at commit `1343a18908c6`
(`external-review/low-latency-reference/HdrHistogram_c`, BSD-2-Clause / CC0-1.0).

## Artifacts

| Artifact | Path | SHA-256 |
|---|---|---|
| HDR histogram (header-only C++20) | `cpp/bench/hdr_histogram.hpp` | *(see `MANIFEST_FASE1.md`)* |
| Unit tests (AFX harness) | `cpp/bench/tests/test_hdr.cpp` | *(see `MANIFEST_FASE1.md`)* |
| CLI driver for the cross-check | `cpp/bench/tools/hdr_cli.cpp` | *(see `MANIFEST_FASE1.md`)* |
| Independent Python reference | `cpp/bench/tools/hdr_reference.py` | *(see `MANIFEST_FASE1.md`)* |
| Cross-check runner + report | `cpp/bench/tools/crosscheck_hdr.py`, `crosscheck_report.json` | *(see `MANIFEST_FASE1.md`)* |
| Red log (test before implementation) | `FASE1/red.log` | *(see `MANIFEST_FASE1.md`)* |
| Green log (test after implementation) | `FASE1/green.log` | *(see `MANIFEST_FASE1.md`)* |
| HDR percentile reports (measured) | `cpp/bench/benchmarks/bench_*_hdr.json` | *(see `MANIFEST_FASE1.md`)* |

SHA-256 values are computed and listed in `MANIFEST_FASE1.md` (generated at
the end of the phase, alongside this file).

## Red → green

1. `cpp/bench/tests/test_hdr.cpp` written FIRST (contract: known values →
   exact percentiles, empty → 0, monotonicity, record bounds, min/max
   semantics, constructor validation, count_at_value, reset, large values).
2. Stub `hdr_histogram.hpp` → suite ran and failed: **3 passed, 7 failed**
   (`FASE1/red.log`).
3. Implementation ported from the HdrHistogram_c bucket-config/index
   arithmetic (same integer math: `largest_value_with_single_unit_resolution
   = 2·10^sigfigs`, sub-bucket counts, `count_at = floor(p/100·total + 0.5)`
   clamped to ≥ 1, highest/lowest equivalent values).
4. Suite ran and passed: **10 passed, 0 failed** (`FASE1/green.log`).

## Cross-check (independent language)

`crosscheck_hdr.py` builds 4 deterministic corpora (seed `20260919`) and
compares the compiled C++ driver against `hdr_reference.py` — the
independent Python re-derivation of the same semantics. Two implementations
in two languages cannot agree by accident.

| Corpus | Values | Result |
|---|---|---|
| `log_uniform` (10^0 … 10^12) | 100,000 | PASS, 0 mismatches |
| `spikes` (clustered + jitter) | 100,000 | PASS, 0 mismatches |
| `heavy_tail` (95% small + 5% stalls) | 100,000 | PASS, 0 mismatches |
| `uniform_small` (1…4096) | 50,000 | PASS, 0 mismatches |

Tolerance (documented in the script): exact equality, or the same
equivalent-value bucket (≤ 1 ULP of the HDR representation). Observed: **0
differences outside tolerance** across 350,000 values × 7 percentiles +
count/min/max. Report: `cpp/bench/tools/crosscheck_report.json` (verdict
`PASS`), copy in `FASE1/crosscheck_report.json`.

## Integration into the measured benchmarks (final mode, held-out sizes)

Same samples as the existing suite, now with p50/p99/p99.9/p99.99 from the
3-significant-figure histogram — all numbers measured on this host
(MSVC cl 14.50 /O2, Windows x64; anti-cheat guards unchanged):

| Benchmark | p50 | p99 | p99.9 | p99.99 | max |
|---|---|---|---|---|---|
| ITCH 5.0 decode | 16 ns | 25 ns | 53 ns | 117 ns | 209 ns |
| Binance SBE decode | 83 ns | 182 ns | 326 ns | 966 ns | 1.92 µs |
| Multicast UDP publish (loopback) | 2.47 µs | 101 µs | 227 µs | 375 µs | 716 µs |
| JSON stdlib decode (baseline) | 1.50 µs | 4.70 µs | 11.4 µs | 48.1 µs | 2.98 ms |

Dev-mode numbers and the full JSONs: `cpp/bench/benchmarks/bench_*_hdr.json`.
The histogram reports only measured samples (batch-timed, batch sizes
declared in each JSON); nothing is estimated or rounded in our favor.

## Verification status

- Suite green: **10/10** (`FASE1/green.log`; also runs inside
  `cpp/build.ps1 -Phase all` and `cpp/build.sh all` on CI).
- Cross-check: **4/4 corpora, 0 mismatches outside tolerance**.
- New measured JSONs written: `bench_itch/sbe/mcast/json_{dev,final}_hdr.json`
  (8 files).
