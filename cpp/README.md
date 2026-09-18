# cpp/ — Low-latency venue connectivity codecs in C++

C++ venue-connectivity layer: **feed
handlers and normalization**, **SBE**, **FIX**, **ITCH**, **OUCH** and
**multicast distribution**, with typed loss recovery and honest measured
benchmarks. Every byte of every codec traces to a captured, SHA256-pinned
specification (nothing invented) and every change was driven test-red →
implementation → test-green.

| Module | What | Spec source | Evidence |
|---|---|---|---|
| `itch/` | Nasdaq TotalView-ITCH 5.0 decoder (S/R/H/A/F/E/C/X/D/U/P/Q/B) | `NQTVITCHSpecification.pdf` SHA256 `45E0531D…AACC3` | `evidence/EVIDENCE_01_ITCH_OUCH.md` |
| `ouch/` | OUCH 5.0 order-entry semantics (UserRefNum, replace chain, outcomes 2.2) | `OUCH5.0.pdf` SHA256 `770253DE…C2C00` + MARKET_MICROSTRUCTURE §5.5 | `evidence/EVIDENCE_01_ITCH_OUCH.md` |
| `sbe/` | Binance Spot SBE decoder (trades/bestBidAsk/depth/depth-diff) | `sbe/schema/stream_1_0.xml` SHA256 `6EA32846…10A1F7` (pinned) | `evidence/EVIDENCE_02_SBE.md` |
| `net/` | Multicast UDP join/leave + sequence recovery (NAK retransmission, snapshot bridging) + SPSC ring | `NETWORKING_DISTRIBUTED_STREAMING.md` §4 + Aeron (design reference) | `evidence/EVIDENCE_03_MULTICAST.md` |
| `recovery/` | Instant typed silence detection (cadence/watchdog) + A/B arbitration + Binance diff-depth book continuity | `ELITE_LOSS_RECOVERY_20260918.md` §0-§4 | `evidence/EVIDENCE_03B_RECOVERY.md` |
| `resilience/` | Layered anti-loss capture: live → cache → REST backfill with `captured-live`/`backfilled` provenance | `ELITE_LOSS_RECOVERY_20260918.md` §6 | `evidence/EVIDENCE_03C_RESILIENCE.md` |
| `fix/` | FIX 4.4 session layer (logon/heartbeat/resend/sequence-reset, NextNumIn/Out persistence) | MARKET_MICROSTRUCTURE §5.5 + QuickFIX reference | `evidence/EVIDENCE_04_FIX.md` |
| `bench/` | Measured benchmarks (p50/p99/throughput, dev+final, anti-cheat) | — | `evidence/EVIDENCE_05_BENCHMARKS.md` |

## Build & test

Windows (MSVC, no cmake — per captured toolchain):
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File cpp\build.ps1 -Phase all
```

Linux (g++, CI leg):
```bash
bash cpp/build.sh all
```

Both regenerate every golden/malformed vector from the pinned generators
before running the suites, so vectors and code always trace to the same spec
bytes.

## Honesty boundaries

- SBE golden vectors are produced with the OFFICIAL Simple Binary Encoding
  code generator (`sbe-all-1.35.1.jar`, SHA256 pinned in `tools/sbe-tool/README.md`);
  the hand-written decoder is cross-checked field-by-field against the
  official generated decoder.
- The Binance SBE production lane is **deferred by policy**
  (`evidence/EVIDENCE_07_SBE_INTEGRATION.md`): the JSON collector gates are
  still open and no Ed25519 market-data-only key was provided.
- Benchmarks are per-host measurements, not cross-vendor claims.

## Live latency probe (measured)

Independent public probe (its own connection; never touches the productive
service): host <-> Binance Spot one-way delay per message and clock-free RTT.
See \probe/REPORT.md\ + \probe/report.json\ (2026-09-18):

- REST RTT median 371.2 ms; WS ping/pong RTT mean 388.3 ms.
- depth BTCUSDT@100ms: delay p50 119.9 ms, p99 131.0 ms (inter-arrival p50
  99.99 ms = 100 ms cadence verified).
- trades: delay p50 124.6 ms, p99 450.0 ms.
- Clock uncertainty declared: +-185.6 ms (no PTP on this host).
