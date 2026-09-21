# EVIDENCE — PHASE 3-B: Instant loss detection + elite recovery (MANDATORY)

**Status: DONE (green).** Date: 2026-09-18. Directory: `cpp/recovery/`.

## Spec used (nothing invented)

- `ELITE_LOSS_RECOVERY_20260918.md` §0-§4 (workspace root) + its annotated
  sources (MoldUDP64, CME MDP 3.0 arbitration/recovery, B3 UMDF
  snapshot/RptSeq).
- `HOT_REDUNDANT_CAPTURE_AUTHORITY_V1.md` (honest Binance boundary: dual feeds
  are independent lanes; the CME A/B algorithm is a contrast, not a Binance
  contract — the arbiter implements the generic pattern with that documented
  boundary).
- `BINANCE_SOURCE_LOCK.md` web-socket-streams.md + MARKET_MICROSTRUCTURE §5.1
  (local book rule: set quantity, zero removes a level, update-id gap → resync).

## Implementation (BOTH mandate cases)

1. **TOTAL SILENCE**: `CadenceGuard` (depth@20ms; no message within 3 windows
   [inside the spec's 2-5 range] = dead, typed instantly), `Watchdog` (5 s
   ping/pong deadline). Typed causes: `transport_dead` / `exchange_silent` /
   `serverShutdown`.
2. **PACKET LOSS (live flow)**: `DualLaneArbiter` — A/B by sequence; a gap on
   ONE lane is typed with the exact range and covered by the other; a gap on
   BOTH = ConsumerGap + `apply_snapshot` (snapshot + sequence bridging).
3. **Book continuity**: `DerivedBook` with the Binance diff-depth rule
   (first==last+1; gap → typed ResyncNeeded, never silent).
4. **Anticipation signals** (`SignalMonitor`): rate deviation, gap frequency,
   RTT trend, preventive rotation at 23 h of 24 h.

## Test red → green

- **RED** (stub): `0 passed, 10 failed, 10 total`.
- **GREEN**: `10 passed, 0 failed, 10 total`.

## Verification required by the instruction

- (a) Total silence → typed detection WITHIN the declared deadline and
  failover to the other lane: `cadence_exchange_silent_within_declared_deadline`
  (no fire at 119 ms, fires `exchange_silent` at 120 ms with 3×20 ms windows)
  + `total_silence_failover_typed_hole` (A dies after seq 10, B resumes at 15,
  hole [11..14] TYPED and B delivers continuously).
- (b) Packet loss on feed A → continuous derived state via B or snapshot with
  the raw gap declared: `ab_arbitration_loss_on_a_covered_by_b` (A loses 5 →
  typed gap [5..5] on A, B covers, zero ConsumerGap) +
  `dual_loss_consumer_gap_and_snapshot_bridge` (loss on both → gap [4..5]
  declared + snapshot bridge at 9 → continuity).
- Real SBE→book integration: `sbe_depth_diff_to_book_integration` (SBE frame
  built with the official encoder, decoded by PHASE 2, applied to the book).

Green log: `cpp/build.ps1 -Phase recovery` (and `ALL_PHASES_GREEN.log`).
