# Architecture — what is built (Phases 1-2)

## Components

1. **Dual-lane hot-redundant capture** (`rust/lob-replay/src/bin/hot_redundant_capture.rs`,
   `raw_campaign.rs`, `segmented_capture.rs`). Two independent lanes (PRIMARY/SHADOW) per
   symbol capture depth and trade streams into ACK-durable raw logs (`.bnraw`) with per-record
   SHA-256 chaining. A pure availability state machine (`hot_redundancy.rs`) schedules bounded
   reconnects, makes no-ready-lane intervals explicit, and enforces a **per-lane circuit
   breaker** (5 consecutive failures → 60 s cooldown → single half-open probe) to avoid
   hammering the venue during outages.

2. **Watchdog ping/pong** (`transport.rs`, wired in both capture binaries). A proactive WS
   PING every 30 s with a 5 s PONG deadline types the failure cause precisely:
   `transport_dead` (no PONG) vs `exchange_silent` (PONGs flow, market data does not — typed
   by the market-freshness layer). Control pings can never mask frozen market data
   (regression-tested).

3. **Canonical Arbitrator** (`live_arbitration.rs`). Trade-union watermark across both lanes
   (strictly increasing IDs, per-lane emission clamps, typed conflicts), order-book depth
   continuity with typed gaps, resume/rebind chaining with a recovered trade floor that
   survives a crash before the first publication (fault-gate defect hrs-7c9c792ca38c).

4. **Sealed hash-chained journal** (`transport_journal.rs`, `segment_chain.rs`). Every record
   carries `previous_record_sha256`; generations seal with manifests and durability ACKs;
   transport events are schema-validated (exact keys) in BOTH languages.

5. **Independent dual-language verification**
   (`rust/lob-replay/src/bin/live_arbitration_verify.rs`,
   `python/src/binance_lob/live_arbitration_verify_cli.py`). Same strict contract, two
   implementations: trades must equal the raw union above the declared floor with exact
   digests and lineage; depth frames must exist in the trusted contiguous prefix of the
   publishing lane with byte-identical book digests. The full replay reconciles
   **byte-identical** (evidence: `evidence/g2-reconciliation.json`).

6. **Fault gates on the real live path** (`scripts/test_continuous_faults.ps1`,
   `test_continuous_service_gate.ps1`). Arbiter crash, supervisor kill, hung verifier are
   injected on the REAL launcher in Continuous mode; recovery is typed and the closed-set
   oracle still verifies.

7. **Kernel ETW network observer** (`kernel_network_trace.rs`) — optional elevated observer
   recording kernel-level socket evidence for the capture window.

## Key invariants (regression-locked)

- Pings never count as market data (`control_pings_cannot_mask_frozen_market_messages`).
- Zero-gaps is FORBIDDEN as a claim: every discontinuity is a typed GAP with an exact reason.
- Historical numbers are sacred: replay verification must reproduce
  1,569,954 / 1,136,854 trades, 862,595 / 843,196 depth frames, 5 gaps + 5 rebootstrap per
  symbol with the same journal SHA-256 (`7CECB611…`, `46BD0CB0…`).
- Every performance optimization is accepted only with a byte-identical output contract test
  (the Python book digest streaming rewrite is property-tested against the legacy serializer).
