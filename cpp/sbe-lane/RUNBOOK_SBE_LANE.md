# RUNBOOK — SBE lane (candidate parallel lane, separate epochs)

Status: **executable and live-verified**. The SBE lane runs as a PARALLEL
CANDIDATE with its own directory, its own epochs and its own key — it never
merges epochs with the JSON lanes (CAPTURE_CAMPAIGN_POLICY_V1.md, "Feed
evolution"). Promotion to a canonical path follows the policy gates (exact
semantic comparison, measurement, recovery, explicit decision).

## Single live-run requirement

A Binance **Ed25519 market-data-only API key** (spec: captured
`sbe-market-data-streams.md`, SHA256 `3E945F52…`; the key travels in the
`X-MBX-APIKEY` header of the WebSocket handshake). Without a key the venue
rejects the handshake (HTTP 400, verified live). The key is taken from the
`BINANCE_SBE_API_KEY` environment variable and is NEVER written to disk.

## Build and test (no key, against a local mock)

```powershell
# Windows
powershell.exe -NoProfile -ExecutionPolicy Bypass -File cpp\build.ps1 -Phase all
python -m pip install "websockets==17.0.1"
$env:PYTHONPATH = "cpp\sbe-lane"
python -m unittest discover -s cpp\sbe-lane\tests -v    # 6/6 green

# Linux
bash cpp/build.sh all
PYTHONPATH=cpp/sbe-lane python3 -m unittest discover -s cpp/sbe-lane/tests -v
```

## Run live (with the key)

```powershell
$env:BINANCE_SBE_API_KEY = "<ED25519_MARKET_DATA_ONLY_KEY>"
python cpp\sbe-lane\sbe_lane.py `
  --url "wss://stream-sbe.binance.com:9443/stream?streams=btcusdt@depth20/btcusdt@depth/btcusdt@trade/btcusdt@bestBidAsk/ethusdt@depth20/ethusdt@depth/ethusdt@trade/ethusdt@bestBidAsk" `
  --out "D:\captures\sbe-20260920" `
  --duration 0 `
  --max-conn-s 82800
```

- `--duration 0` = run until rotation/termination; `--max-conn-s 82800` =
  23 h (venue limit: 24 h per connection; preventive rotation like the JSON
  lane).
- The key is NOT written to any output file (it travels only in the
  handshake; the journal records `api_key_present: true` without the key).

## What it writes (create-only, all inside --out)

| File | Content |
|---|---|
| `frames.sbe` | raw SBE frames, u32-LE length prefixed |
| `sbe-events.jsonl` | SHA-256 hash-chained journal: LANE_START, FRAME (sha256+template_id), SERVER_SHUTDOWN, CONN_CLOSED, TRANSPORT_DEAD, GAP_TYPED (exact wall range between connections), LANE_END |
| `sbe-terminal.json` | terminal inventory: files, bytes, SHA-256, frame count |
| `sbe-telemetry.jsonl` | per frame: venue event_time_us (first schema field) + local receive wall/monotonic |

## Verify a run

```powershell
cpp\build\bin\sbe_decode_cli.exe <dir>\frames.sbe            # JSON per frame, exit 0 = all decoded
cpp\build\bin\sbe_decode_cli.exe --summary <dir>\frames.sbe  # per-template counts, no per-frame spam
python cpp\sbe-lane\measure_sbe_lane.py --dir <dir> --out measure.json   # wire-leg delay p50/p99
python latency-probe-20260918\audit_sbe_lane.py <dir> cpp\build\bin\sbe_decode_cli.exe  # streaming audit
```

The decoder is the PHASE 2 one (pinned schema `6EA32846…`, cross-checked
against the official Simple Binary Encoding code generator).

## End-to-end measurement (instrumented)

Every captured frame writes `sbe-telemetry.jsonl` with the **venue event time**
(first schema field, `eventTime` µs at offset 8 — read from the frame itself)
and the **local receive instant**. `measure_sbe_lane.py` computes the wire-leg
distribution per message type with a clock offset measured against
`/api/v3/time` (declared uncertainty ±RTT/2, ~±190 ms on this host without
PTP). The LOCAL legs (receive→store→decode) are ns/µs and are measured by the
PHASE 5 benchmarks (SBE decode 83 ns p50) — the network dominates by ~5
orders of magnitude.

## How we decide a run is "perfect" (measurable criteria)

| # | Criterion | How it is measured | Expected on this host |
|---|---|---|---|
| 1 | Real cadence | `measure_sbe_lane.py` inter-arrival | depth@20ms → p50 ≈ 20 ms; no untyped silent windows |
| 2 | Zero corruption | `sbe_decode_cli.exe --summary <dir>\frames.sbe` | exit 0 over 100% of the frames |
| 3 | Journal integrity | re-verification of the SHA-256 chain | valid chain; inter-connection holes = `GAP_TYPED`, zero silence |
| 4 | End-to-end delay | `measure_sbe_lane.py` | wire p50 ≈ 125 ms (measured), bounded p99, declared uncertainty |
| 5 | Semantic equality vs JSON | overlapping window of both lanes | identical trades by trade id; book converges (policy promotion gate) |
| 6 | Rotation | `--max-conn-s 82800` | 23 h without loss, rotation hole TYPED |

**"Perfect" = criteria 1-4 without a single exception over the full run, plus
5 on the comparison window, plus the formal acceptance of the JSON endurance
gate (policy).** Until then the lane is a candidate with measured evidence,
not a claim.

## Declared limits

- The lane is a CANDIDATE; the JSON path remains the correctness oracle.
- Holes between connections stay TYPED with the exact wall range; zero silent
  loss.
- Reconciliation against the venue REST backfill (aggTrades/depth) for lost
  windows is the documented layer in `cpp/resilience/` (EVIDENCE_03C) —
  integrating it into this lane is the next policy step, not a replacement of
  the current gate.
