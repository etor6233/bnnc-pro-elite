# EVIDENCE — PHASE 3-C: Layered anti-loss architecture (MANDATORY)

**Status: DONE (green).** Date: 2026-09-18. Directory: `cpp/resilience/`.

## Spec used (nothing invented)

- `ELITE_LOSS_RECOVERY_20260918.md` §6 (THE DEFINITIVE ANTI-LOSS SOLUTION):
  1. source duplication (two independent paths of the same datum);
  2. layered failover FCP (live feed → local cache → venue API → REST);
  3. gap reconciliation against the authoritative source after recovery;
  4. backfill from the venue's historical record (Binance REST
     aggTrades/depth, pinned in `BINANCE_SOURCE_LOCK.md` rest-api.md);
  5. provenance chain: `captured-live` | `backfilled` + hash, never a silent
     mix.

## Implementation (`cpp/resilience/`)

- `LayeredCapture`: per-sequence journal with declared per-record provenance +
  content hash (FNV-1a 32); dedup across redundant paths keeping the first
  path's provenance; layered failover with documented order (live → cache →
  REST backfill); injectable backfill (`BackfillFn`), whose production
  binding is Binance REST aggTrades/depth (documented; requires live access
  and key — declared boundary in the header).
- `reconcile()`: authoritative reconciliation — complete only if EVERY
  sequence emitted by the venue (1..high) is present as recoverable content;
  gap-typed records make the reconciliation INCOMPLETE with the exact missing
  range.

## Test red → green

- **RED** (stub): `0 passed, 5 failed, 5 total`.
- **GREEN**: `5 passed, 0 failed, 5 total`.

## Verification required by the instruction

A test that kills an entire path, recovers via the other + backfill, and
proves the final dataset contains EVERYTHING the venue emitted with declared
provenance:

- `kill_entire_live_path_rest_backfill_recovers_all`: venue emits 1..25; A
  dies after 10; REST backfill recovers 11..24 (`backfilled`); a new live feed
  delivers 25 (`captured-live`); reconcile vs venue=25 → COMPLETE; each range
  with its exact provenance.
- `cache_layer_serves_first_then_rest_backfill`: FCP order verified (local
  cache before REST; cached content keeps `captured-live`).
- `dual_path_source_duplication_no_loss`: two independent paths, A dies at
  15, B covers; 25/25 live, zero loss.
- `unrecoverable_window_typed_gap_exact_range`: if even the venue backfill
  lacks sequence 11 → it stays TYPED [11..11] and reconcile = INCOMPLETE
  (honesty: completeness is never faked).
- `journal_hashes_bind_every_record`: per-record hash + first-path provenance
  preserved.

Green log: `cpp/build.ps1 -Phase resilience` (and `ALL_PHASES_GREEN.log`).
