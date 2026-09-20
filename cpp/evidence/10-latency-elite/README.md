# Evidence 10 — latency elite campaign (2026-09-19)

Evidence trail for the latency-engineering campaign (scientific percentile
measurement, false-sharing/cache-line/lock-free evidence, Aeron IPC demo,
kernel-bypass design documentation, publication). Every artifact is listed
with its SHA-256 in the per-phase manifests; nothing here is estimated.

| Phase | What | Evidence |
|---|---|---|
| FASE 1 | HDR latency histogram in C++ (p50/p99/p99.9/p99.99), cross-validated | `FASE1/` (red/green logs, crosscheck report) + `../../bench/hdr_histogram.hpp` + `../../bench/tests/test_hdr.cpp` + `../../bench/tools/crosscheck_hdr.py` + `../../bench/benchmarks/*_hdr.json` |
| FASE 2 | False sharing / cache-line / SPSC ring, measured with HDR percentiles | `FASE2/` + `../../bench/bench_false_sharing.cpp` + `../../bench/bench_spsc.cpp` + `../../net/tests/test_spsc.cpp` + `../../bench/benchmarks/bench_false_sharing_*.json`, `bench_spsc_*.json` |
| FASE 3 | Aeron IPC demo, real run, measured with the official HdrHistogram jar | `FASE3/AERON_IPC_REPORT.md` + `FASE3/MANIFEST_FASE3.md` |
| FASE 4 | Kernel-bypass design reference (DPDK / OpenOnload / Machnet), no fake runs | `FASE4/MANIFEST_FASE4.md` + `../../bench/KERNEL_BYPASS_DESIGN.md` |
| FASE 5 | CI artifacts + static benchmark page + 5-minute verification | `FASE5/` + `../../../.github/workflows/ci.yml` + `../../../bench-latency/index.html` |
| FASE 6 | Professional presentation + final scan | `FASE6/` + `../../ACTA_FINAL_LATENCY_ELITE_20260919.md` |

Rules applied throughout (see the campaign instruction §3): every algorithm
traces to a pinned elite source (captures under
`external-review/low-latency-reference/`, commits listed in its INDEX.md);
red → green discipline with both logs saved; metrics only measured (dev and
final modes, anti-cheat guards); nothing prohibited was touched.
