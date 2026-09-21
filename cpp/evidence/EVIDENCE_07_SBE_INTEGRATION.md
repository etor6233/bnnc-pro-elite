# EVIDENCE — PHASE 7: SBE integration per policy

**Status: LANE EXECUTABLE as a parallel candidate; PROMOTION deferred by
policy (allowed by the mandate: "documented deferral decision").** Date:
2026-09-18/19.

## The lane runs — only the key was needed (and it worked)

- `cpp/sbe-lane/sbe_lane.py`: SBE capture with its OWN epochs (never merged
  with JSON), SHA-256 hash-chained journal, TYPED holes between connections
  (`GAP_TYPED` with the exact wall range), typed `serverShutdown`, preventive
  rotation at 23 h, Ed25519 key via the `X-MBX-APIKEY` header (never written
  to disk).
- `cpp/sbe-lane/sbe_decode_cli.cpp`: verification CLI decoding captured
  frames with the PHASE 2 decoder (pinned schema `6EA32846…`); `--summary`
  mode counts per template for multi-million-frame captures.
- Red-green tests `cpp/sbe-lane/tests/test_sbe_lane.py`: **6/6 green** against
  a local mock server serving the official-encoder goldens — (1) byte-identical
  capture + valid journal + exact CLI decode, (2) ping→pong + typed
  `serverShutdown`, (3) reconnect with `GAP_TYPED`, (4) measure-script math,
  (5) API key sent as `X-MBX-APIKEY` and never on disk, (6) `--summary` mode.
- **Live campaign executed**: the user's API key validated (`ACCEPTED_101`);
  23 h cycle with 13,253,624 frames, 0 typed gaps, full decode 100% OK —
  see `EVIDENCE_09_LIVE_SBE_CAMPAIGN.md`.
- Runbook: `cpp/sbe-lane/RUNBOOK_SBE_LANE.md` (build, test, run live,
  verify). CI runs the lane suite on Linux+Windows.

## The applicable policy

`Binance/docs/CAPTURE_CAMPAIGN_POLICY_V1.md` "Feed evolution" (lines 256-263):

> JSON `depth@100ms` plus individual `trade` remains the correctness oracle.
> Once the continuous JSON collector passes its gates, SBE `depth` at 20 ms and
> SBE trades become a parallel candidate using a separate Ed25519
> market-data-only key. JSON and SBE retain separate epochs and dataset
> versions. SBE can be promoted only after exact semantic comparison,
> latency/CPU measurement, recovery tests and an explicit compatibility
> decision.

And "Promotion sequence" item 8: "only then consider SBE promotion and
economic feature/model gates" — after JSON gates 1-7.

## Real state vs policy preconditions

| Policy precondition | Observed state | Consequence |
|---|---|---|
| Continuous JSON collector with passed gates (items 1-7) | The productive service (24 h+ soak) is RUNNING; the endurance gate acceptance remains the project's own step | SBE PROMOTION stays deferred |
| Separate Ed25519 market-data-only key | PROVIDED by the owner; venue accepted it (101) | Lane RUNS live |
| JSON and SBE with independent epochs/dataset versions | Implemented: `cpp/sbe-lane/` writes its own epochs (`sbe-…`) and never touches JSON trees | Met by construction |
| Exact semantic comparison, latency/CPU measurement, recovery tests | COMPLETED: PHASE 2 decoder cross-checked against the official codegen, PHASE 5 benchmarks (83 ns p50, p99.99 966 ns), PHASE 3-B/3-C recovery, lane 6/6 vs mock | Technical preconditions covered |

## What is ready (and where the evidence is)

- SBE decoder for the pinned schema with official-encoder goldens: `cpp/sbe/`
  (EVIDENCE_02_SBE.md).
- **Executable SBE lane**: `cpp/sbe-lane/` with capture, typed journal,
  verification CLI and 6/6 green tests against a local mock
  (`RUNBOOK_SBE_LANE.md`).
- SBE decode benchmarks (PHASE 5) and SBE→book recovery (PHASE 3-B).
- **Live 23 h campaign with full decode verification**
  (EVIDENCE_09_LIVE_SBE_CAMPAIGN.md).

## Decision

- **RUN the lane**: enabled once the key exists — executed and verified
  (EVIDENCE_09). The lane runs as a parallel candidate with independent
  epochs — exactly what the policy allows.
- **PROMOTE SBE to a canonical path**: deferred until the JSON endurance
  gate passes and the promotion sequence completes (exact semantic
  comparison, measurement, recovery, explicit decision).

Measurable acceptance criteria for a run (cadence, zero corruption, journal
integrity, end-to-end delay, semantic equality vs JSON on the overlap
window, 23 h rotation): `cpp/sbe-lane/RUNBOOK_SBE_LANE.md`, section "How we
decide a run is perfect".