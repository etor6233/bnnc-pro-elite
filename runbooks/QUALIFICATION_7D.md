# Seven-day continuous raw qualification

This runbook governs the first `CONTINUOUS_DATASET` release gate after an exact
`ENDURANCE_24H` pass. It captures public Binance Spot `BTCUSDT` and `ETHUSDT`
only. Credentials and order entry remain absent.

## Exact topology

- capture horizon: `604800 s` (seven days);
- raw storage segment: `900 s`, without reconnecting;
- planned WebSocket generation slots: every `82800 s` (23 hours);
- A/B overlap: `900 s`;
- exact terminal cardinality per symbol: eight generations, seven proven
  handovers and eight planned launches;
- accepted unexpected-shutdown paths: zero;
- independent terminal verification: Rust and Python over every immutable raw
  byte after capture, outside the capture horizon.

Every overlap remains immutable raw evidence under separate generation and
connection-epoch identities. The released/canonical consumer later chooses one
owner at each proven boundary; it does not concatenate files, glob directories
or delete duplicate overlap evidence.

## Preconditions

The current source hashes must pass format, Rust/Python tests, clippy, the real
retained-handle fault gate and a fresh dual-symbol smoke. A historical campaign
that passed on older launcher/monitor bytes does not qualify changed source.
Windows Time must be healthy; the gate is not weakened for stale-time status.

The launcher creates a source-only `sealed-runtime` under the new run root and
executes the campaign coordinators, capture children, Rust verifier and Python
verifier source from that sealed bundle. Worktree caches and later development
edits are outside the campaign execution boundary.

## Preflight and launch

From an elevated, operator-owned 64-bit Windows PowerShell:

```powershell
Set-Location -LiteralPath "C:\Users\NL\Desktop\NEW BINANCE\Binance"

powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File ".\scripts\run_24h_raw_qualification.ps1" `
  -Mode SevenDay -ValidateOnly

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File ".\scripts\run_24h_raw_qualification.ps1" `
  -Mode SevenDay
```

`SevenDay` fixes all topology and verification budgets; an explicit conflicting
override is rejected. Its default evidence root is
`artifacts/qualification-7d-raw`.

Leave the foreground PowerShell open. A chat/browser disconnect does not own
the process, but closing the PowerShell, logging off, sleeping, rebooting or an
actual market-transport failure fails the active qualification and preserves
its exact evidence.

## Read-only monitoring

Use the exact run root printed by `READY`:

```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File ".\scripts\monitor_24h_raw_qualification.ps1" `
  -RunRoot "<run-root>"
```

`HEALTHY_RUNNING` requires current market freshness, durable progress, exact
process identity, hash-linked journals, healthy host/clock evidence and no
failure event. After capture ends, `VERIFYING` is expected until both oracles
finish for both symbols. Only the exact terminal `COMPLETE` plus a fresh
read-only terminal monitor qualifies the seven-day window.

## Continuity semantics

The seven-day process is a bounded reliability gate, not the final indefinite
service. Within it, each old WebSocket remains active until its successor has a
snapshot, durable overlap and exact depth/trade handover proof. No market event
is silently removed: raw overlap may contain the same venue event in A and B,
while the future canonical view owns it exactly once.

If Internet/transport fails, the gate fails closed. Later collection starts a
fresh epoch after bounded recovery and a new official snapshot bridge; it never
claims that an unobserved interval was continuous. After this gate passes, the
next implementation step is rolling immutable release windows over a collector
that keeps running, so dataset qualification and collection availability no
longer share one terminal deadline. The exact boundary and implementation order
are fixed in `docs/CONTINUOUS_DATASET_V1.md`; this bounded runbook does not
pretend that service already exists.
