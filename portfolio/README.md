# Portfolio — reviewer entry point

This page is the single entry point for a technical reviewer evaluating this
repository. It says what the system is, what is verified, where the evidence
lives, and how to reproduce it in about five minutes. Every claim below links
to a committed evidence file — numbers in this repository are measured or
archived, never asserted without a trail.

**System in one sentence:** a hot-redundant, hash-chained market-data capture
and verification platform for Binance Spot public data (BTCUSDT/ETHUSDT),
with an independent dual-language correctness oracle, Windows operational
supervision, and a C++ low-latency venue-connectivity layer — all
spec-pinned, tested red-to-green, and benchmarked with HDR percentiles.

Public market data only. No account credentials, order entry, trading
signals, or profitability claims anywhere in this repository.

## What is built and verified

### Part 1 — Production capture with forensic integrity (the core)

Dual-lane hot-redundant raw capture (`PRIMARY` + `SHADOW` websocket lanes)
feeding a canonical arbitrator that emits a sealed, SHA-256 hash-chained
journal. The system makes silent loss impossible by construction: every
discontinuity becomes a **typed GAP record** (`unprovable_continuation`,
`transport_dead`, `exchange_silent`) that is counted and auditable.

- **Independent dual-language oracles.** Rust and Python verifiers must agree;
  the historical replay (1.57M records per symbol) reconciles **byte-identical**
  (`evidence/g2-reconciliation.json`, verdict `PASS`).
- **Fault gates injected on the real live path.** Arbiter crash mid-publication,
  supervisor kill, hung verifier — injected, recovered, and typed; the
  closed-set oracle still verifies (`verified=true`, `errors=[]`).
- **Production soak, live:** the running service has soaked **>45 h** with
  per-epoch verification passing in both languages (Rust + Python) —
  `evidence/live-run-24h/SUMMARY.md` plus the campaign audit trail.
- **Instant typed loss recovery** (cadence + watchdog silence detection, A/B
  arbitration, Binance diff-depth book continuity) and **layered anti-loss
  capture** (live → cache → REST backfill with `captured-live`/`backfilled`
  provenance) — `cpp/evidence/EVIDENCE_03B_RECOVERY.md`,
  `cpp/evidence/EVIDENCE_03C_RESILIENCE.md`.

### Part 2 — Dataset engineering and integrity

Sealed epochs, planned handovers with overlap (capture never stops),
per-lane circuit breakers, and the replay/reconciliation machinery that the
oracles run on. Status and entry/exit criteria: `docs/ROADMAP.md` (phases
described honestly; no speculative code committed ahead of its gate).

### C++ venue-connectivity layer (low-latency codecs)

Every codec built from a captured, SHA256-pinned specification with
test-red → implementation → test-green discipline:

- **ITCH 5.0** decoder and **OUCH 5.0** order-entry semantics —
  `cpp/evidence/EVIDENCE_01_ITCH_OUCH.md`
- **SBE** decoder for the pinned Binance Spot schema, cross-checked
  field-by-field against the official code generator —
  `cpp/evidence/EVIDENCE_02_SBE.md`
- **Multicast UDP** transport with sequence recovery, NAK retransmission and
  snapshot bridging — `cpp/evidence/EVIDENCE_03_MULTICAST.md`
- **FIX 4.4** session layer (logon/heartbeat/resend/sequence-reset) —
  `cpp/evidence/EVIDENCE_04_FIX.md`
- **Lock-free SPSC ring** with compile-time cache-line guarantees —
  `cpp/net/include/net/spsc_ring.hpp` + `cpp/evidence/10-latency-elite/`

### Latency engineering, measured (2026-09-19 campaign)

- **HDR latency histogram in C++** (3 significant figures, [1 ns, 1 h])
  with p50/p99/p99.9/p99.99 — implemented from the HdrHistogram_c semantics
  (BSD-2/CC0, commit `1343a18908c6`) and cross-validated against an
  independent Python re-derivation on 4 synthetic corpora with **0
  mismatches outside tolerance** —
  `cpp/bench/hdr_histogram.hpp`, `cpp/bench/tools/crosscheck_hdr.py`,
  `cpp/bench/tools/crosscheck_report.json`
- **False-sharing / cache-line evidence, measured** — the same two counters
  in one cache line vs `alignas(64)`-separated, with HDR percentiles —
  `cpp/bench/bench_false_sharing.cpp` + `cpp/bench/benchmarks/bench_false_sharing_*.json`
- **SPSC ring benchmark (1P/1C)** with explicit-overflow retry counts and HDR
  percentiles — `cpp/bench/benchmarks/bench_spsc_*.json`
- **Aeron IPC demo, real and measured** — official `aeron-all` jar from
  Maven Central, `aeron:ipc`, 1,000,000 messages, p50/p90/p99/p99.9/p99.99
  recorded by the official HdrHistogram jar —
  `cpp/evidence/10-latency-elite/FASE3/AERON_IPC_REPORT.md`
- **Kernel-bypass design reference** (DPDK / OpenOnload / Machnet) with
  pinned-commit citations and an honest "not executed on this host" status —
  `cpp/bench/KERNEL_BYPASS_DESIGN.md`
- **Benchmarks with p50/p99/p99.9/p99.99 on every codec** (dev + final
  modes, anti-cheat: fresh outputs, volatile sink, no memoization) —
  `cpp/bench/benchmarks/` and the rendered report `bench-latency/index.html`

### Live measurements

- Independent latency probe host ↔ Binance (its own connection, never
  touching the productive service): depth p50 119.9 ms / p99 131.0 ms, RTT
  371–388 ms, declared uncertainty ±186 ms without PTP —
  `cpp/probe/REPORT.md`
- Live SBE capture campaign audit: hash-chain verified, zero gaps, 20k/20k
  decode — `cpp/evidence/EVIDENCE_09_LIVE_SBE_CAMPAIGN.md`

## Five-minute verification

Clone, build, test, and see the benchmark report — no API keys needed:

```bash
git clone https://github.com/etor6233/bnnc-pro-elite.git
cd bnnc-pro-elite

# Linux (g++, CI leg):
bash cpp/build.sh all                      # all C++ suites + HDR cross-check
bash cpp/bench/run_benchmarks.sh dev       # measured benchmarks (dev mode)

# Windows (MSVC):
powershell -NoProfile -ExecutionPolicy Bypass -File cpp\build.ps1 -Phase all
powershell -NoProfile -ExecutionPolicy Bypass -File cpp\bench\run_benchmarks.ps1 -Mode dev
```

Then open `bench-latency/index.html` (or read the JSONs directly under
`cpp/bench/benchmarks/`) and check the CI badge on the README — the same
suites run green on Linux and Windows in GitHub Actions on every push.

The Aeron IPC demo re-runs with one command (needs a JDK 21):
`powershell -ExecutionPolicy Bypass -File cpp\evidence\10-latency-elite\FASE3\aeron-ipc\run_aeron_ipc_demo.ps1`

## Honest status

What is **verified** (evidence-linked above): Parts 1–2 built and gate-tested,
soak >45 h, C++ suites green on both platforms, SBE campaign audited, and the
latency suite measured end to end.

What is **not claimed**: order-book/trading logic beyond the roadmap gates,
kernel-bypass hardware runs (documented design only — no dedicated NICs on
the development host), cross-vendor benchmark comparisons (numbers are
per-host measurements), and zero-gap history (gaps are typed, counted and
audited — never erased).

## Design boundaries

- Preserve bytes before interpretation; raw overlap is retained, not erased.
- Separate venue time, receive time and monotonic time; timestamp precision
  does not establish one-way latency accuracy.
- Binance diff-depth is aggregated L2, not a complete order-by-order log.
- A sequence gap or unproven boundary is surfaced; no interpolation, no
  fabricated continuity.
- A successful replay is not a performance benchmark and a benchmark is not
  a production track record.

---

Protocol authority: pinned Binance Spot documentation (commit
`976cc580553890e92031b77306147c0ed1de5a46`). Evidence index for every claim:
`docs/EVIDENCE.md`. Full architecture: `docs/ARCHITECTURE.md`.
