# REPORT — Measured host ↔ Binance Spot latency (2026-09-18, two runs)

Independent probe (new directory `latency-probe-20260918/`): opens its own
public connection and does NOT touch the productive 24 h service (verified
alive and writing during the same period), XERJ, journals or frozen
binaries.

## Method (declared, nothing estimated)

1. **Clock offset** local↔venue: `GET https://api.binance.com/api/v3/time`
   ×12 (endpoint pinned in `BINANCE_SOURCE_LOCK.md` rest-api.md, SHA256
   `49EA6809…`); offset = serverTime − (local send time + RTT/2); median.
2. **Per-message delay**: combined public stream
   `/stream?streams=btcusdt@depth@100ms/btcusdt@trade` on
   `stream.binance.com:9443` (pinned web-socket-streams.md, SHA256
   `32BF73A0…`); per message:
   `delay = local_receive_time − (E_event_time_ms + median_offset)`.
   `E` is the venue event time (spec). Declared uncertainty:
   ±median_RTT/2 (network asymmetry not observable without PTP).
3. **Clock-free RTT**: WebSocket ping/pong (3 replies) and REST RTT (12) —
   figures that do not depend on the offset.
4. The data phase is PURE receive (no stalls): pings were done afterwards so
   they cannot contaminate the distribution (a first attempt with interleaved
   pings inflated p99 to ~10 s by self-induced queueing — corrected and
   documented).

## Measured results (report.json)

| Metric | 1st run (20:28Z) | 2nd run (21:5xZ) |
|---|---|---|
| REST RTT median (`/api/v3/time` ×12) | 371.2 ms | 387.1 ms |
| **Depth BTCUSDT@100ms: delay p50** | **119.9 ms** | **120.3 ms** |
| Depth: delay p99 / mean / max | 131.0 / 121.3 / 386.2 ms | 133.1 / 121.6 / 282.8 ms |
| Depth: inter-arrival p50 / p99 | 99.99 / 110.2 ms | 100.01 / 112.4 ms |
| **Trade BTCUSDT: delay p50** | **124.6 ms** | **123.0 ms** |
| Trade: delay p99 / mean / max | 450.0 / 131.8 / 451.0 ms | 228.0 / 126.7 / 289.7 ms |
| Samples | 1785 depth + 3726 trades | 1786 depth + 2244 trades |
| Delay uncertainty (clock) | ±185.6 ms | ±193.5 ms |

Two independent runs: depth p50 119.9 vs 120.3 ms and trades 124.6 vs
123.0 ms — stable.

## Honest reading

- The pure NETWORK component (clock-free) is **RTT/2 ≈ 185–194 ms** one way.
- The effective event→receive delay measures **p50 ≈ 120–125 ms** with
  ±186–194 ms uncertainty; depth p99 ~131 ms and trade p99 ~228–450 ms
  (trade bursts delivered together in the same aggregation window).
- The ~120 ms vs RTT/2 186 ms are compatible within the declared clock
  uncertainty: no precision better than that range is claimed WITHOUT
  verified PTP/NTP — exactly the boundary the project declares (a timestamp
  is not accuracy without a documented clock domain).
- The depth cadence (100 ms) was verified by measurement: p50 99.99 ms.

Files: `probe.py` (reproducible), `report.json` (exact figures).
