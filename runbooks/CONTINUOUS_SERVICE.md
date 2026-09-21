# Runbook — continuous hot-redundant service with live arbitration (ADR-17)

Scope: BTCUSDT/ETHUSDT, continuous dual-lane raw capture, arbitrated
canonical view, sealed and verified qualification windows. Nothing here
trains ML, places orders or deletes raw automatically.

Commands run from `<WORKSPACE>\Binance`.

## 1. Preflight (does not start capture)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\run_hot_redundant_qualification.ps1 -Mode ValidateOnly
```

Check the output: `status=PASS`, binary/script/source hashes, free disk >=
required, healthy clock. **Production requires an elevated console**
(kernel ETW).

Note (verified 2026-09-16 against the launcher): `-Mode ValidateOnly` is NOT
strictly read-only: without `-ReleaseBinRoot` it builds `--release` in
`Binance\target\release` before printing the preflight (same-binary
guarantee). To validate an already-frozen bundle without rebuilding, pass
`-ReleaseBinRoot <frozen path>` (accepted in ValidateOnly; REJECTED in
`-Mode Production`).

## 2. Continuous start (production; do not start without independent review)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\run_hot_redundant_qualification.ps1 -Mode Continuous
```

(`-EpochWindowSeconds 14400` is the default; `-TimeScale 1` is the default
and mandatory in real operation: `TimeScale > 1` accelerates milestones AND
activates the reduced test topology. Without `-SkipKernelObserver`: the
elevated observers stay enabled; the launcher requires an elevated console
except for an explicit typed-skip test invocation.)

The service:
- has no global horizon (never ends by duration);
- renews each symbol supervisor every `EpochWindowSeconds` (default 4 h) with
  planned overlap: the successor starts `EpochWindowSeconds - overlap` before
  the predecessor seals; a symbol's two lanes never stop before a READY
  successor;
- seals and verifies every epoch window (Rust + Python) while the next one
  captures;
- supervises the per-symbol canonical arbiter: any exit is recovered with
  `--resume` (durable identity + segment chain, no duplication or rollback)
  and backoff; the derived view degrades without touching raw;
- emits `WINDOW_MILESTONE` at 24 h / 7 d / 30 d without stopping capture;
- keeps `stop.request` as the single cooperative stop mechanism.

Evidence: `artifacts\hrs\hrs-<nonce>\` (service-events.jsonl, preflight,
terminal, canonical-live/<symbol>/*-seg-*.jsonl, trade-identity.bin).

## 3. Status

```powershell
Get-Content artifacts\hrs\hrs-<nonce>\service-events.jsonl -Tail 50
# events: SERVICE_READY, SYMBOL_EPOCH_RENEWED (no_outer_gap), WINDOW_MILESTONE,
# LIVE_ARBITRATION_LAUNCHED/SEGMENT_SEALED/SEGMENT_VERIFIED, OBSERVER_FAILED, ...
Get-Content artifacts\hrs\hrs-<nonce>\service-terminal.json   # after stop
```

## 4. Safe stop (cooperative, lossless)

```powershell
# create the stop file empty (create-only)
[IO.File]::WriteAllBytes("artifacts\hrs\hrs-<nonce>\stop.request", [byte[]]@())
```

The service: finishes the current epoch, drains supervisors (1800 s cap),
completes the pending transition (arbiter rebind), seals the last segment,
verifies the canonical set against the raw oracle (Rust + Python, PASS
identity mandatory) and writes `service-terminal.json` with an honest state
(`PASS` / `CAPTURE_COMPLETE_WITH_EXPLICIT_GAPS` /
`CAPTURE_COMPLETE_WITH_OBSERVABILITY_FAILURES`). Processes live in a
kill-on-close Job Object; the `finally` guarantees cleanup.

## 5. Restart / recovery

A restart is simply a new `-Mode Continuous` with a new `hrs-<nonce>` (new
root, new mutex). AUTOMATIC recovery inside a run covers:

- arbiter down → `LIVE_ARBITRATION_EXITED_EARLY` + relaunch with `--resume`
  (the new segment chains `ARBITRATION_RESUMED` with
  `previous_journal_sha256` + `trade_floor` + `previous_tail_bytes`);
- symbol supervisor down → `OUTER_GAP_OPENED/CLOSED` + backoff; the planned
  successor promotes without a gap;
- hung evaluator → termination at the monotonic deadline,
  `LIVE_ARBITRATION_AUDIT_TIMEOUT`; the auditor also cleans up when its
  arbiter dies;
- disk below the reserve (100 GiB) → `STORAGE_SAFE_STOP_REQUESTED` + evidenced
  safe stop; raw is never deleted automatically.

## 6. Quarantine / derived-view degradation

If the canonical view cannot be proven (typed conflict, unbridgeable gap,
failed verification), the arbiter fails closed: it stops publishing, writes
the typed event and exits non-zero. Raw keeps capturing. Window promotion
requires `oracle_identity=PASS` on BOTH verifiers; `SKIPPED`, timeout or
pending audit never promotes.

## 7. Retention / disks / observers

- Persistent reserve: 100 GiB; preflight validates projected space with a
  safety factor.
- No automatic raw deletion; the retention policy is decided by the operator
  outside the service.
- Kernel ETW + network witness: per-epoch deadline (rotation), per-window
  sealed evidence; in non-elevated test runs the terminal records an honest
  `SKIPPED_NOT_ELEVATED` (the elevated gate stays OPEN).

## 8. Upgrades

Freeze sources → full release build (`cargo build --release -p lob-replay
--bin hot_redundant_capture --bin hot_redundant_verify --bin raw_campaign
--bin segmented_capture --bin campaign_verify --bin kernel_network_trace
--bin live_arbitration --bin live_arbitration_verify`) → full Rust/Python
suites → fmt/clippy → live/launcher/fault gates with THOSE binaries → new
manifest with hashes. Changing anything afterwards invalidates the affected
gates: repeat them.

## 9. Honest limits

- An event lost on BOTH lanes is not provable without a third witness that
  Binance does not offer without credentials (contract boundary).
- Real 24 h / 7 d soak: real-time gate, separate from preparation.
- Elevated kernel ETW: requires an elevated console (explicit gate).
- Full oracle verification of a 24 h window: tens of minutes (full book
  digest per frame); per-epoch verifications use the bounded
  `--tail-segment-only` mode.