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
