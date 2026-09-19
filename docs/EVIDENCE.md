# Evidence index

Every number quoted in the README traces to a file here or in `evidence/`.

| Claim | Evidence |
|---|---|
| Fault gate `verified=true` | `evidence/gates/fault-gate-20260917-closure.log` + `.exit` |
| Service gate `errors=[]`, `outer_gaps=0`, 27/27 renewals | `evidence/gates/service-gate-20260917-closure.log` + `.exit` |
| G2 replay byte-identical reconciliation | `evidence/g2-reconciliation.json` (verdict PASS; python reports SHA-256 equal to historical) |
| Frozen release identity | `evidence/frozen-release-manifest-20260917.json` (toolchain, sources tree hashes, binaries SHA-256, code identity vs fault doubles) |
| Production 24h soak | `evidence/live-run-24h/SUMMARY.md` + `preflight.json` + per-epoch verification reports (Rust + Python PASS) |
| Sample data | `samples/canonical-btcusdt-sample.jsonl`, `samples/raw-btcusdt-sample.jsonl` |

## Venue-connectivity layer (C++, 2026-09-18)

| Claim | Evidence |
|---|---|
| ITCH 5.0 + OUCH 5.0 codecs green (5/5 + 11/11) | \cpp/evidence/EVIDENCE_01_ITCH_OUCH.md\ + \cpp/evidence/logs/ALL_PHASES_GREEN_20260918.log\ |
| SBE decoder matches the official generated decoder field-by-field | \cpp/evidence/EVIDENCE_02_SBE.md\; schema pin SHA256 \6EA328467E144311B1F1EFFF38E9FE613829997F041DD02A3B7077885D10A1F7\ in \cpp/NOTICE.md\ |
| Multicast loss ? NAK ? retransmission e2e (12/12) | \cpp/evidence/EVIDENCE_03_MULTICAST.md\ |
| Typed silence detection + A/B arbitration (10/10) | \cpp/evidence/EVIDENCE_03B_RECOVERY.md\ |
| Layered failover + backfill provenance (5/5) | \cpp/evidence/EVIDENCE_03C_RESILIENCE.md\ |
| FIX session recovery (10/10) | \cpp/evidence/EVIDENCE_04_FIX.md\ |
| Benchmarks measured (SBE 83 ns p50 decode; JSON stdlib 1500 ns p50) | \cpp/bench/benchmarks/bench_*.json\ + \cpp/evidence/EVIDENCE_05_BENCHMARKS.md\ |
| SBE lane deferred by capture policy | \cpp/evidence/EVIDENCE_07_SBE_INTEGRATION.md\ |
| CI green Linux + Windows | \.github/workflows/ci.yml\ + GitHub Actions checkmark |

| CI green Linux + Windows (run 35387520776) | \cpp/evidence/EVIDENCE_06_CI.md\ |
| Publication scan: no secrets, no personal paths | \cpp/evidence/EVIDENCE_08_PUBLICATION.md\ |
| Final act with the complete DONE checklist | \cpp/ACTA_FINAL_VENUE_CONNECTIVITY_20260918.md\ |

| Live latency probe host <-> venue (depth p50 119.9 ms, RTT 371-388 ms, +-186 ms) | \cpp/probe/REPORT.md\ + \cpp/probe/report.json\ |

| Live SBE campaign audit (11h, 4.52M frames, chain OK, 0 gaps, 20k/20k decode) | \cpp/evidence/EVIDENCE_09_LIVE_SBE_CAMPAIGN.md\ |
