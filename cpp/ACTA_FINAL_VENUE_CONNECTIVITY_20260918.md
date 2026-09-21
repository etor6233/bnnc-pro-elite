# FINAL REPORT — C++ venue-connectivity layer + CI + benchmarks (2026-09-18)

Full execution of the venue-connectivity engineering instruction (PHASES 1-8
— C++ venue connectivity, typed loss recovery, measured benchmarks, CI and
publication) without touching the productive service, XERJ, historical
journals, the holdout or the frozen release binaries. All new work lives in
the new `cpp/` directory of the workspace and was published to the public
repository `etor6233/bnnc-pro-elite` (branch `main`).

## DONE checklist (each item with its evidence file)

| Item | Status | Evidence file |
|---|---|---|
| PHASE 0: references captured with SHA256 + INDEX | [x] (pre-existing, 2026-09-18) | `external-review/low-latency-reference/INDEX.md` + `BINANCE_SOURCE_LOCK.md` |
| PHASES 1-4: ITCH/SBE/OUCH-semantics codecs + FIX session, green suites | [x] DONE | `cpp/evidence/EVIDENCE_01…04` (see the per-phase evidence index); 57/57 green in `cpp/evidence/logs/ALL_PHASES_GREEN_20260918.log` |
| PHASE 5: measured benchmarks published | [x] DONE | `cpp/bench/benchmarks/bench_*_final.json` + `cpp/evidence/EVIDENCE_05_BENCHMARKS.md` |
| PHASE 6: CI green on Linux + Windows | [x] DONE | `.github/workflows/ci.yml`; green runs incl. `35387520776`, `35388366114` + `cpp/evidence/EVIDENCE_06_CI.md` |
| PHASE 7: SBE integration per policy (documented deferral + executable lane) | [x] DONE | `cpp/evidence/EVIDENCE_07_SBE_INTEGRATION.md` (policy cited; lane executable, 6/6 vs mock; promotion deferred per policy) |
| PHASE 8: public repo updated, scanned (no secrets, no personal paths) | [x] DONE | `cpp/evidence/EVIDENCE_08_PUBLICATION.md` (merge on `main`, README/EVIDENCE aligned, clean scan) |
| Final report: every README claim points to an evidence file | [x] DONE | This file + the README venue-connectivity section + `docs/EVIDENCE.md` |

## Phase summary (test red → green, captured specs)

| Phase | What | RED | GREEN |
|---|---|---|---|
| 1 | ITCH 5.0 (17 golden, 8 malformed) | 1/5 | **5/5** |
| 1 | OUCH 5.0 semantics (8 golden + 7 scenarios) | 1/11 | **11/11** |
| 2 | Binance SBE + official-codegen cross-check | 1/4 | **4/4** |
| 3 | Multicast UDP + sequence recovery (loss→NAK→retransmission e2e) | 2/12 | **12/12** |
| 3-B | Typed total-silence detection + A/B arbitration + Binance book | 0/10 | **10/10** |
| 3-C | Layered anti-loss + backfill with provenance | 0/5 | **5/5** |
| 4 | FIX session (logon/heartbeat/resend/reset/persistence) | golden-driven | **10/10** |
| 5 | Benchmarks dev+final | — | 8 measured JSONs |
| 6 | GitHub Actions CI Linux+Windows | 2 red runs (toolchain/deps) | **GREEN 4/4 jobs** |
| 7 | SBE integration | — | documented deferral per policy |
| 8 | Publication | — | merge on `main`, clean scan |

## Honest boundaries

- Professional employment history is NOT replaced by this repository; it is
  compensated with measurable evidence only. Nothing in the repo claims
  otherwise.
- No work-authorization claim is made anywhere in the repository.
- The repo never claims zero-gaps: holes are TYPED with their exact range
  (gap-typed / ConsumerGap / ResyncNeeded) — see the 3/3-B/3-C suites.
- Historical project numbers (trades, depth, journal SHA256) were not
  touched or rewritten by any new file.
- The productive service, XERJ, historical journals, holdout and frozen
  binaries were NOT touched: all new work lives in `cpp/` and in the clean
  clone at `cpp/public-repo/`, never in the live tree.


## PRODUCTION HANDOFF — 2026-09-21 (recorded state before restart)

- Previous continuous run (`hrs-5971e1d2cb41`): **86.4 h healthy** at stop
  decision — journal hash-chain advancing, 23 processes (dual-lane raw +
  live arbitration sidecar), 20 symbol epochs launched/ready, zero raw-lane
  gaps/deaths/silences; 50 typed `OBSERVER_FAILED` events accumulated on the
  live-arbitration sidecar (typed, visible; raw capture unaffected). Expected
  honest terminal after the cooperative stop:
  `CAPTURE_COMPLETE_WITH_OBSERVABILITY_FAILURES`.
- SBE parallel campaign (`captura-sbe-20260919b`): completed its full 23 h
  cycle cleanly — 13,253,624 frames, 0 typed gaps, full decode
  13,253,624/13,253,624 OK (see EVIDENCE_09).
- Restart command (elevated console, from `Binance\`):
  `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\run_hot_redundant_qualification.ps1 -Mode Continuous`
  (defaults: EpochWindowSeconds 14400, TimeScale 1; no global horizon).
- Checkpoints of the NEW run: `WINDOW_MILESTONE` events at **24 h / 7 d /
  30 d** in `artifacts\hrs\hrs-<nonce>\service-events.jsonl`; terminal state
  after the next cooperative stop must be verified in both verifiers.