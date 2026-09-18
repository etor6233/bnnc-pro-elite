# Production 24h soak — summary (run hrs-5971e1d2cb41)

- **Started**: 2026-09-17 23:16:42 local · **Verified through**: 11 h 38 m (summary written
  mid-soak; run left running to complete 24 h).
- **Preflight**: `PASS` (see `preflight.json` — binaries, sources, disk, clock).
- **Service**: `SERVICE_READY` reached for BTCUSDT + ETHUSDT; planned epoch renewals with
  overlap (capture never stops); per-epoch sealed windows verified **PASS in Rust and Python**
  (`b1/b2/e1/e2-*.json` — `gaps: []`, lanes `VERIFIED_COMPLETE`).
- **Canonical journals**: hash-chained segments growing continuously (BTC 513k+ / ETH 512k+
  records at 11h38m), fresh writes every second.
- **Typed gaps (honest, declared)**: 2 per symbol at epoch handovers —
  `unprovable_continuation` on the DEPTH stream (book handover cannot be proven continuous, so
  it is declared). Trade stream: zero gaps (global increasing IDs).
- **Live independent verification** (read-only, against the active segment + raw oracle):
  `status=PASS, oracle_identity=PASS` for both symbols.
- **Typed observer events** at the first handover (verifier raced the terminal record, sidecar
  stop deadline, prefix-audit deadline) — all recovered, retried and passed on the second
  epoch; none produced silent loss.
- **Self-maintenance**: process count oscillates 12↔22 across handovers and returns by itself
  (cooperative drain + monotonic deadlines + kill-on-close job object). No manual cleanup.
