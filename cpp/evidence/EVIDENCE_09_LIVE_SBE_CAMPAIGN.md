# EVIDENCE — Live SBE campaign (parallel candidate lane, 2026-09-19/20)

**Status: COMPLETED AND FULLY VERIFIED.** The lane ran its full 23 h cycle
(start 2026-09-19 12:54:44 local, clean `LANE_END` at 2026-09-20 11:55:31 —
the planned rotation before the venue's 24 h connection limit). The user's
Ed25519 key was validated by the venue (`ACCEPTED_101`) and was never written
to disk.

## Accumulated data (final, measured)

| Metric | Value MEASURED |
|---|---|
| Duration of data | 23 h (13,253,624 frames) |
| Journal hash-chain (SHA-256) | **VALID** (13,253,625 records; streaming audit) |
| Events | LANE_START ×1, FRAME ×13,253,624, LANE_END ×1 — **0 GAP_TYPED, 0 SERVER_SHUTDOWN, 0 TRANSPORT_DEAD** |
| Key on disk | **0 matches** (full output scan) |
| **Full decode of the entire capture** | **13,253,624 / 13,253,624 frames OK, 0 errors** (C++ decoder, `sbe_decode_cli --summary`, exit 0) |
| Frames by type | trades 572,153 · bestBidAsk 3,620,448 · depth20 3,073,857 · depth-diff 5,987,166 |
| Raw bytes | 3.19 GB frames.sbe (+ 6.0 GB hash-chained journal + 1.7 GB telemetry) |

## Cadence measured (inter-arrival, two symbols combined)

| Stream (template) | p50 | p99 |
|---|---|---|
| depth diff @20ms (10003) | 16 ms | 50 ms |
| depth20 @50ms (10002) | 40 ms | 62 ms |
| bestBidAsk (10001, on-change) | 2 ms | 292 ms |
| trade (10000, event-driven) | 42 ms | 1143 ms |

## End-to-end delay measured (venue E → local receive; offset via
`/api/v3/time`, declared uncertainty ±187.7 ms without PTP)

| Stream | p50 | p99 | mean |
|---|---|---|---|
| depth diff @20ms | **125.5 ms** | 172.9 ms | 127.8 ms |
| depth20 @50ms | 125.5 ms | 161.6 ms | 127.6 ms |
| bestBidAsk | 126.7 ms | 418.1 ms | 133.5 ms |
| trade | 126.4 ms | 257.1 ms | 131.3 ms |

## Honest comparison against the previous JSON campaign (no SBE)

| Dimension | JSON (previous) | SBE (this campaign) | Real improvement |
|---|---|---|---|
| Book cadence | depth@100ms (10/s) | depth@20ms (50/s) | **5× temporal density** (52.6 diffs/s measured live) |
| Message size | ~600 B (JSON depth) | 82–114 B (SBE depth diff) | **~5–7× fewer bytes** |
| Local decode | 1,500 ns p50 (json.loads) | **83 ns p50** (PHASE 2 decoder) | **~18×** |
| Network delay (venue→host) | p50 119.9–120.3 ms | p50 125.5–126.7 ms | **no change** (same network/venue; inside the ±188 ms uncertainty) |
| Extra data types | — | bestBidAsk (auto-culling) + depth20 top-20 | **yes** |
| Per-frame telemetry | not per-message | venue-E + recv per frame + SHA-256 chain | **yes** |

Honest conclusion: the network dominates the delay on both paths
(~120–126 ms); SBE does not reduce network latency — it wins on **density,
size, decode cost and per-frame evidence**. That is exactly the claim made.

## Reproducible audit

```powershell
python latency-probe-20260918\audit_sbe_lane.py <capture-dir> cpp\build\bin\sbe_decode_cli.exe
cpp\build\bin\sbe_decode_cli.exe --summary <capture-dir>\frames.sbe
```

(streaming: does not stop the capture, does not load the journal in memory).
